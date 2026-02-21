#include "uring.h"

// Cold-path io_uring implementations — called once at startup.
// Hot-path functions remain static inline in uring.h.

// io_uring ring mmap setup
static int uring_mmap(struct uring *ring, const struct io_uring_params *p) {
    struct uring_sq *sq = &ring->sq;
    struct uring_cq *cq = &ring->cq;
    size_t size;
    int ret;

    // SQ ring mapping.
    // With NO_SQARRAY, sq_off.array is 0, so use CQ end as size.
    if (p->flags & IORING_SETUP_NO_SQARRAY)
        size = p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe);
    else
        size = p->sq_off.array + p->sq_entries * sizeof(u32);
    sq->ring_sz = size;
    sq->ring_ptr = (u8 *)mmap(NULL, size, PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_POPULATE, ring->ring_fd,
                              IORING_OFF_SQ_RING);
    if (unlikely(IS_MMAP_ERR(sq->ring_ptr)))
        return MMAP_ERR(sq->ring_ptr);

    // CQ ring mapping
    // With SINGLE_MMAP (common), SQ and CQ share one map.
    if (p->features & IORING_FEAT_SINGLE_MMAP) {
        cq->ring_ptr = sq->ring_ptr;
        cq->ring_sz = 0;
    } else {
        size = p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe);
        cq->ring_sz = size;
        cq->ring_ptr = (u8 *)mmap(NULL, size, PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_POPULATE, ring->ring_fd,
                                  IORING_OFF_CQ_RING);
        if (unlikely(IS_MMAP_ERR(cq->ring_ptr))) {
            ret = MMAP_ERR(cq->ring_ptr);
            munmap(sq->ring_ptr, sq->ring_sz);
            return ret;
        }
    }

    // SQE array mapping
    size = p->sq_entries * sizeof(struct io_uring_sqe);
    sq->sqes = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE, ring->ring_fd,
                    IORING_OFF_SQES);
    if (unlikely(IS_MMAP_ERR(sq->sqes))) {
        ret = MMAP_ERR(sq->sqes);
        if (cq->ring_sz)
            munmap(cq->ring_ptr, cq->ring_sz);
        munmap(sq->ring_ptr, sq->ring_sz);
        return ret;
    }

    // Setup SQ pointers
    sq->khead = (u32 *)(sq->ring_ptr + p->sq_off.head);
    sq->ktail = (u32 *)(sq->ring_ptr + p->sq_off.tail);
    sq->kring_mask = (u32 *)(sq->ring_ptr + p->sq_off.ring_mask);
    sq->kring_entries = (u32 *)(sq->ring_ptr + p->sq_off.ring_entries);
    sq->kflags = (u32 *)(sq->ring_ptr + p->sq_off.flags);
    sq->kdropped = (u32 *)(sq->ring_ptr + p->sq_off.dropped);
    // Cache frequently-used values
    sq->ring_mask = *sq->kring_mask;
    sq->ring_entries = *sq->kring_entries;
    sq->cached_khead = 0; // Kernel starts at 0

    if (!(p->flags & IORING_SETUP_NO_SQARRAY)) {
        sq->array = (u32 *)(sq->ring_ptr + p->sq_off.array);
        // Pre-fill SQ array with identity mapping.
        // Since we use SINGLE_ISSUER, sequential allocation, and contiguous submission,
        // array[n % size] = n % size is always correct. This enables O(1) submit.
        mem_iota_u32(sq->array, sq->ring_entries);
    }

    // Setup CQ pointers
    cq->khead = (u32 *)(cq->ring_ptr + p->cq_off.head);
    cq->ktail = (u32 *)(cq->ring_ptr + p->cq_off.tail);
    cq->kring_mask = (u32 *)(cq->ring_ptr + p->cq_off.ring_mask);
    cq->kring_entries = (u32 *)(cq->ring_ptr + p->cq_off.ring_entries);
    cq->kflags = (u32 *)(cq->ring_ptr + p->cq_off.flags);
    cq->koverflow = (u32 *)(cq->ring_ptr + p->cq_off.overflow);
    cq->cqes = (struct io_uring_cqe *)(cq->ring_ptr + p->cq_off.cqes);

    // Cache ring mask
    cq->ring_mask = *cq->kring_mask;

    return 0;
}

int uring_init(struct uring *ring, u32 sq_entries, u32 cq_entries) {
    struct io_uring_params p = {0};
    *ring = (struct uring){0};
    int ret;

    // DEFER_TASKRUN subsumes COOP_TASKRUN — kernel ignores COOP when DEFER is set
    u32 flags = IORING_SETUP_SUBMIT_ALL |
                IORING_SETUP_SINGLE_ISSUER |
                IORING_SETUP_DEFER_TASKRUN |
                IORING_SETUP_CQSIZE;

    p.flags = flags | IORING_SETUP_NO_SQARRAY;
    p.cq_entries = cq_entries;

    ring->ring_fd = io_uring_setup(sq_entries, &p);
    if (ring->ring_fd == -EINVAL) {
        // Kernel may not support NO_SQARRAY — retry without.
        // Reset p fully since kernel may have partially modified it.
        p = (struct io_uring_params){0};
        p.flags = flags;
        p.cq_entries = cq_entries;
        ring->ring_fd = io_uring_setup(sq_entries, &p);
    }
    if (unlikely(ring->ring_fd < 0))
        return ring->ring_fd;

    ring->features = p.features;
    ring->flags = p.flags;  // Store what kernel accepted
    ring->registered_index = -1;  // Not yet registered

    ret = uring_mmap(ring, &p);
    if (unlikely(ret < 0)) {
        close(ring->ring_fd);
        return ret;
    }

    // Register the ring fd — skips fd→file lookup per io_uring_enter() call
    // (~40-60 cycles saved per syscall). Requires kernel 6.4+.
    struct io_uring_rsrc_update up = { .offset = (u32)-1, .data = ring->ring_fd };
    int rr = io_uring_register(ring->ring_fd, IORING_REGISTER_RING_FDS, &up, 1);
    if (rr == 1)
        ring->registered_index = (int)up.offset;
    // else: fallback — registered_index stays -1, uses raw ring_fd

    return 0;
}

int uring_register_fixed_files(struct uring *ring, u32 count) {
    // Try sparse registration first (kernel 5.19+) — kernel initializes
    // empty table internally, no userspace allocation needed.
    struct io_uring_rsrc_register reg = {
        .nr = count,
        .flags = IORING_RSRC_REGISTER_SPARSE,
    };
    int ret = io_uring_register(ring->ring_fd, IORING_REGISTER_FILES2,
                                &reg, sizeof(reg));
    if (ret >= 0)
        return ret;

    // Fallback: allocate sparse fd array, fill with -1
    size_t size = count * sizeof(int);
    int *fds = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(fds))
        return MMAP_ERR(fds);

    mem_fill_nt(fds, 0xFF, size);  // -1 = empty slot

    ret = io_uring_register(ring->ring_fd, IORING_REGISTER_FILES, fds, count);
    munmap(fds, size);  // Kernel copied it, we can free
    return ret;
}

// Register a single buffer ring with kernel
static int buf_ring_register(struct uring *ring, void *ring_addr,
                              u16 num_entries, u16 bgid) {
    struct io_uring_buf_reg reg = {0};
    reg.ring_addr = (u64)ring_addr;
    reg.ring_entries = num_entries;
    reg.bgid = bgid;
    return io_uring_register(ring->ring_fd, IORING_REGISTER_PBUF_RING, &reg, 1);
}

// Unregister a single buffer ring from kernel
static int buf_ring_unregister(struct uring *ring, u16 bgid) {
    struct io_uring_buf_reg reg = { .bgid = bgid };
    return io_uring_register(ring->ring_fd, IORING_UNREGISTER_PBUF_RING, &reg, 1);
}

int buf_ring_mgr_init(struct uring *ring, struct buf_ring_mgr *mgr,
                       const struct buf_ring_config *configs,
                       u8 num_configs) {
    if (num_configs > BUF_RING_MAX_GROUPS)
        return -EINVAL;

    *mgr = (struct buf_ring_mgr){0};

    // Calculate total size needed for all groups
    size_t total = 0;
    size_t bitmap_sizes[BUF_RING_MAX_GROUPS] = {0};
    for (int i = 0; i < num_configs; i++) {
        if (configs[i].num_buffers > BUF_RING_MAX_BUFFERS)
            return -EINVAL;
        if ((configs[i].num_buffers & (configs[i].num_buffers - 1)) != 0)
            return -EINVAL;  // Must be power of 2
        total += sizeof(struct io_uring_buf) * configs[i].num_buffers;
        total += (size_t)configs[i].buffer_size * configs[i].num_buffers;
        // Calculate bitmap size for ZC groups (round up to 64-byte alignment)
        if (brc_is_zc(&configs[i])) {
            size_t bitmap_bytes = ((configs[i].num_buffers + 63) / 64) * sizeof(u64);
            bitmap_sizes[i] = (bitmap_bytes + 63) & ~(size_t)63;
            total += bitmap_sizes[i];
        }
    }

    // Attempt mmap with huge pages
    void *ptr = mmap(NULL, total, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
    if (IS_MMAP_ERR(ptr)) {
        LOG_WARN("huge pages unavailable for buf_ring_mgr, falling back");
        ptr = mmap(NULL, total, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
        if (IS_MMAP_ERR(ptr))
            return MMAP_ERR(ptr);
    }

    mgr->base = ptr;
    mgr->total_size = total;

    // Layout groups sequentially
    size_t offset = 0;
    for (int i = 0; i < num_configs; i++) {
        struct buf_ring_group *g = &mgr->groups[i];
        u16 num_buffers = configs[i].num_buffers;
        u16 bgid = configs[i].bgid;
        size_t ring_size = sizeof(struct io_uring_buf) * num_buffers;
        size_t data_size = (size_t)configs[i].buffer_size * num_buffers;

        // Invariant: bgid must equal array index for destroy to work
        // (bgid is derived from index, not stored)
        if (bgid != (u16)i)
            return -EINVAL;

        g->ring_offset = (u32)offset;
        g->data_offset = (u32)(offset + ring_size);
        g->buffer_size = configs[i].buffer_size;
        g->buffer_shift = configs[i].buffer_shift;
        g->mask = num_buffers - 1;  // num_buffers derived as mask + 1
        g->tail = 0;

        // Register this group with kernel (bgid = array index)
        int ret = buf_ring_register(ring, (char*)ptr + g->ring_offset,
                                     num_buffers, bgid);
        if (ret < 0) {
            // Cleanup already registered groups (bgid = index)
            for (int j = 0; j < i; j++)
                buf_ring_unregister(ring, (u16)j);
            munmap(ptr, total);
            mgr->base = NULL;
            return ret;
        }

        if (brc_is_zc(&configs[i])) {
            // is_zc derived from free_bitmap != NULL
            g->free_count = num_buffers;
            // Bitmap is allocated after data region
            g->free_bitmap = (u64 *)((char *)ptr + offset + ring_size + data_size);
            size_t bitmap_words = (num_buffers + 63) / 64;
            for (size_t w = 0; w < bitmap_words; w++)
                g->free_bitmap[w] = ~0ULL;
            // Clear trailing bits if not power-of-64 aligned
            u16 trailing = num_buffers & 63;
            if (trailing)
                g->free_bitmap[(num_buffers - 1) >> 6] &= (1ULL << trailing) - 1;
            // Initialize free_summary: all words with free buffers
            g->free_summary = (u16)((1U << bitmap_words) - 1);
        } else {
            g->free_bitmap = NULL;  // is_zc = false (derived from this)
            g->free_summary = 0;
            // Init buffers for recv mode (pre-fill ring)
            struct io_uring_buf_ring *br = BUF_RING_PTR(mgr, g);
            for (u32 j = 0; j < num_buffers; j++) {
                struct io_uring_buf *buf = &br->bufs[g->tail & g->mask];
                buf->addr = (u64)BUF_RING_ADDR(mgr, g, j);
                buf->len = g->buffer_size;
                buf->bid = (u16)j;
                g->tail++;
            }
            smp_store_release(&br->tail, g->tail);
        }

        offset += ring_size + data_size + bitmap_sizes[i];
    }

    mgr->meta.num_groups = num_configs;
    mgr->meta.initialized = 1;
    return 0;
}

void buf_ring_mgr_destroy(struct uring *ring, struct buf_ring_mgr *mgr) {
    // bgid = array index (invariant enforced in init)
    for (int i = 0; i < mgr->meta.num_groups; i++) {
        buf_ring_unregister(ring, (u16)i);
    }
    if (mgr->base) {
        munmap(mgr->base, mgr->total_size);
        mgr->base = NULL;
    }
    mgr->meta.num_groups = 0;
    mgr->meta.initialized = 0;
}

int buf_ring_zc_probe(struct uring *ring) {
    size_t probe_size = sizeof(struct io_uring_probe) + 256 * sizeof(struct io_uring_probe_op);
    size_t alloc_size = (probe_size + 63) & ~(size_t)63;

    struct io_uring_probe *probe = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (IS_MMAP_ERR(probe))
        return -ENOMEM;

    mem_zero_aligned(probe, alloc_size);

    int ret = io_uring_register(ring->ring_fd, IORING_REGISTER_PROBE, probe, 256);
    if (ret < 0) {
        munmap(probe, alloc_size);
        return ret;
    }

    int supported = (probe->last_op >= IORING_OP_SEND_ZC) &&
                    (probe->ops[IORING_OP_SEND_ZC].flags & IO_URING_OP_SUPPORTED);

    munmap(probe, alloc_size);
    return supported ? 0 : -EOPNOTSUPP;
}
