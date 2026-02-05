#pragma once

#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <linux/time_types.h>

// Socket command definitions for async setsockopt (kernel 6.7+)
#ifndef SOCKET_URING_OP_SETSOCKOPT
#define SOCKET_URING_OP_SETSOCKOPT 0
#endif

#ifndef IORING_OP_URING_CMD
#define IORING_OP_URING_CMD 46
#endif

// IORING_SETUP_NO_SQARRAY: added in Linux 6.6, eliminates SQ array indirection
#ifndef IORING_SETUP_NO_SQARRAY
#define IORING_SETUP_NO_SQARRAY (1U << 16)
#endif

// IORING_FILE_INDEX_ALLOC: kernel allocates fixed file slot (direct accept)
#ifndef IORING_FILE_INDEX_ALLOC
#define IORING_FILE_INDEX_ALLOC (~0U)
#endif

// Zerocopy constants (kernel 6.10+)
#ifndef IORING_OP_SEND_ZC
#define IORING_OP_SEND_ZC 53
#endif

#ifndef IORING_RECVSEND_BUNDLE
#define IORING_RECVSEND_BUNDLE (1U << 1)
#endif

#ifndef IORING_CQE_F_NOTIF
#define IORING_CQE_F_NOTIF (1U << 3)
#endif

// Buffer ring configuration limits
enum {
    BUF_RING_MAX_GROUPS  = 4,
    BUF_RING_MAX_BUFFERS = 8192,
};

/* Memory barriers — compiler intrinsics handle per-arch semantics:
   x86-TSO: plain mov + compiler barrier. ARM/RISC-V: ldar/stlr or fence. */
#define smp_load_acquire(p)     __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define smp_store_release(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)

// Ring structures - cache-line optimized layout
struct uring_sq {
    // Kernel-shared pointers - read frequently
    u32 *khead;            // Consumer head (kernel updates)
    u32 *ktail;            // Producer tail (we update)
    u32 *kring_mask;       // Cached on init
    u32 *kring_entries;    // Cached on init
    u32 *array;            // SQE index array
    struct io_uring_sqe *sqes;  // SQE array

    // Local state - not shared with kernel
    u32 ring_mask;         // Cached from *kring_mask
    u32 ring_entries;      // Cached from *kring_entries
    u32 sqe_head;          // Our head for tracking submissions
    u32 sqe_tail;          // Our tail for tracking submissions
    u32 cached_khead;      // Cached kernel head - avoid repeated loads

    // Init-time only
    u32 *kflags;
    u32 *kdropped;
    size_t ring_sz;
    u8 *ring_ptr;
};

struct uring_cq {
    // Kernel-shared pointers
    u32 *khead;            // Consumer head (we update)
    u32 *ktail;            // Producer tail (kernel updates)
    struct io_uring_cqe *cqes;  // CQE array

    // Cached values
    u32 ring_mask;

    // Init-time only
    u32 *kring_mask;
    u32 *kring_entries;
    u32 *kflags;
    u32 *koverflow;
    size_t ring_sz;
    u8 *ring_ptr;
};

struct uring {
    struct uring_sq sq;
    struct uring_cq cq;
    int ring_fd;
    u32 features;
    u32 flags;  // Accepted setup flags
};

// Unified buffer ring system - supports multiple groups in single mmap
// Configuration for a single buffer group
struct buf_ring_config {
    u16 num_buffers;       // Must be power of 2, max BUF_RING_MAX_BUFFERS
    u16 bgid;              // Buffer group ID for kernel registration
    u32 buffer_size;       // Size of each buffer
    u32 buffer_shift;      // log2(buffer_size) for fast address calc
#ifdef ENABLE_ZC
    u8 is_zc;              // Zerocopy mode (bitmap tracking)
#endif
};

// Per-group descriptor - offsets into shared allocation
struct buf_ring_group {
    u16 tail;              // Local tail for ring operations
    u16 mask;              // num_buffers - 1
    u16 bgid;              // Buffer group ID
    u16 num_buffers;       // Number of buffers in this group
    u32 buffer_size;       // Size of each buffer
    u32 buffer_shift;      // log2(buffer_size)
    u32 ring_offset;       // Offset into shared mmap for ring header
    u32 data_offset;       // Offset into shared mmap for buffer data
#ifdef ENABLE_ZC
    u8 is_zc;              // Zerocopy mode flag
    u16 free_count;        // Number of free buffers (ZC only)
    uint64_t free_bitmap[BUF_RING_MAX_BUFFERS / 64];  // 1=free, 0=in-flight
#endif
};

// Unified buffer ring manager - single mmap for all groups
struct buf_ring_mgr {
    void *base;                 // Single mmap base address
    size_t total_size;          // Total mmap size
    struct buf_ring_group groups[BUF_RING_MAX_GROUPS];
    u8 num_groups;         // Currently registered groups
};

// Legacy single-group struct for backwards compatibility
struct buf_ring {
    struct io_uring_buf_ring *br;
    u8 *buf_base;
    u16 tail;
    u16 mask;              // NUM_BUFFERS - 1, cached
    u32 buffer_size;
    u32 buffer_shift;
};

// Buffer ring accessor macros - fast, no function call overhead
#define BUF_RING_PTR(mgr, grp) \
    ((struct io_uring_buf_ring *)((char*)(mgr)->base + (grp)->ring_offset))

#define BUF_RING_DATA(mgr, grp) \
    ((u8 *)((char*)(mgr)->base + (grp)->data_offset))

#define BUF_RING_ADDR(mgr, grp, idx) \
    (BUF_RING_DATA(mgr, grp) + ((u32)(idx) << (grp)->buffer_shift))

// syscall wrappers; no liburing
#define io_uring_setup(entries, params) \
    (int)syscall(__NR_io_uring_setup, (entries), (params))

#define io_uring_register(fd, opcode, arg, nr_args) \
    (int)syscall(__NR_io_uring_register, (fd), (opcode), (arg), (nr_args))

// io_uring initialization
static int uring_mmap(struct uring *ring, struct io_uring_params *p) {
    struct uring_sq *sq = &ring->sq;
    struct uring_cq *cq = &ring->cq;
    size_t size;
    int ret;

    /* SQ ring mapping.
       With NO_SQARRAY, sq_off.array is 0, so use CQ end as size. */
    if (p->flags & IORING_SETUP_NO_SQARRAY)
        size = p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe);
    else
        size = p->sq_off.array + p->sq_entries * sizeof(u32);
    sq->ring_sz = size;
    sq->ring_ptr = (u8 *)mmap(NULL, size, PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_POPULATE, ring->ring_fd,
                              IORING_OFF_SQ_RING);
    if (unlikely(sq->ring_ptr == MAP_FAILED))
        return -errno;

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
        if (unlikely(cq->ring_ptr == MAP_FAILED)) {
            ret = -errno;
            munmap(sq->ring_ptr, sq->ring_sz);
            return ret;
        }
    }

    // SQE array mapping
    size = p->sq_entries * sizeof(struct io_uring_sqe);
    sq->sqes = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE, ring->ring_fd,
                    IORING_OFF_SQES);
    if (unlikely(sq->sqes == MAP_FAILED)) {
        ret = -errno;
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
        /* Pre-fill SQ array with identity mapping.
           Since we use SINGLE_ISSUER, sequential allocation, and contiguous submission,
           array[n % size] = n % size is always correct. This enables O(1) submit. */
        for (u32 i = 0; i < sq->ring_entries; i++) {
            sq->array[i] = i;
        }
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

static int uring_init(struct uring *ring) {
    struct io_uring_params p;
    int ret;

    memset(&p, 0, sizeof(p));
    memset(ring, 0, sizeof(*ring));

    u32 flags = IORING_SETUP_SUBMIT_ALL |
                IORING_SETUP_SINGLE_ISSUER |
                IORING_SETUP_DEFER_TASKRUN |
                IORING_SETUP_COOP_TASKRUN |
                IORING_SETUP_CQSIZE;

    p.flags = flags | IORING_SETUP_NO_SQARRAY;
    p.cq_entries = CQ_ENTRIES;

    ring->ring_fd = io_uring_setup(SQ_ENTRIES, &p);
    if (ring->ring_fd < 0 && errno == EINVAL) {
        /* Kernel may not support NO_SQARRAY — retry without.
           Reset p fully since kernel may have partially modified it. */
        memset(&p, 0, sizeof(p));
        p.flags = flags;
        p.cq_entries = CQ_ENTRIES;
        ring->ring_fd = io_uring_setup(SQ_ENTRIES, &p);
    }
    if (unlikely(ring->ring_fd < 0))
        return -errno;

    ring->features = p.features;
    ring->flags = p.flags;  // Store what kernel accepted

    ret = uring_mmap(ring, &p);
    if (unlikely(ret < 0)) {
        close(ring->ring_fd);
        return ret;
    }

    return 0;
}

// SQE fetch - OPTIMIZED: no memset, minimal work
static inline struct io_uring_sqe *uring_get_sqe(struct uring *ring) {
    struct uring_sq *sq = &ring->sq;
    u32 next = sq->sqe_tail + 1;

    // Fast path: check against cached head (no memory barrier needed)
    if (unlikely(next - sq->cached_khead > sq->ring_entries)) {
        // Slow path: ring looks full, reload head from kernel
        sq->cached_khead = smp_load_acquire(sq->khead);
        if (next - sq->cached_khead > sq->ring_entries)
            return NULL;
    }

    struct io_uring_sqe *sqe = &sq->sqes[sq->sqe_tail & sq->ring_mask];
    sq->sqe_tail = next;

    // NO MEMSET - caller must initialize all required fields explicitly
    return sqe;
}

/* O(1) submit - relies on identity mapping array[n] = n pre-filled at init.
   Invariant: ktail == sqe_head at entry (SINGLE_ISSUER + sequential alloc).
   Requirements: SINGLE_ISSUER, sequential allocation, contiguous submission. */
static inline int uring_submit(struct uring *ring) {
    struct uring_sq *sq = &ring->sq;
    u32 to_submit = sq->sqe_tail - sq->sqe_head;

    if (!to_submit)
        return 0;

    // Invariant: *ktail == sqe_head, so new ktail = sqe_head + to_submit = sqe_tail
    smp_store_release(sq->ktail, sq->sqe_tail);
    sq->sqe_head = sq->sqe_tail;

    return (int)to_submit;
}

static inline int uring_submit_and_wait(struct uring *ring,
                                         unsigned wait_nr,
                                         struct __kernel_timespec *ts) {
    int to_submit = uring_submit(ring);
    unsigned flags = IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG;

    /* Pre-zeroed template avoids memset on every iteration.
       Only sigmask_sz and ts need values; rest must be 0 for kernel. */
    struct io_uring_getevents_arg arg = {
        .sigmask_sz = _NSIG / 8,
        .ts = (uint64_t)ts,
    };

    long ret = syscall(__NR_io_uring_enter, ring->ring_fd, to_submit, wait_nr,
                       flags, &arg, sizeof(arg));

    if (unlikely(ret < 0)) {
        ret = -errno;
        if (ret != -ETIME && ret != -EINTR)
            return (int)ret;
    }

    return to_submit;
}

/* Hot path - inline, no validation in production
   IMPORTANT: Does NOT issue memory barrier. Caller MUST call buf_ring_sync()
   after batching recycles to make buffers visible to kernel. */
static inline void buf_ring_recycle(struct buf_ring *br, u16 bid) {
    DEBUG_ONLY(if (bid > br->mask) { LOG_BUG("invalid bid %u", bid); return; });

    u16 tail = br->tail;
    struct io_uring_buf *buf = &br->br->bufs[tail & br->mask];

    buf->addr = (uint64_t)(br->buf_base + ((u32)bid << br->buffer_shift));
    buf->len = br->buffer_size;
    buf->bid = bid;

    br->tail = tail + 1;
    // NO barrier - call buf_ring_sync() after batch
}

// Publish recycled buffers to kernel. Call once after batch of buf_ring_recycle()
static inline void buf_ring_sync(struct buf_ring *br) {
    smp_store_release(&br->br->tail, br->tail);
}

// Fixed file registration for direct accept
static int uring_register_fixed_files(struct uring *ring, u32 count) {
    // Allocate sparse fd array - all slots initialized to -1
    size_t size = count * sizeof(int);
    int *fds = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    if (fds == MAP_FAILED)
        return -errno;

    memset(fds, -1, size);  // -1 = empty slot

    int ret = io_uring_register(ring->ring_fd, IORING_REGISTER_FILES, fds, count);
    munmap(fds, size);  // Kernel copied it, we can free
    return ret;
}

// Unified buffer ring manager - coalesced allocation for all groups
// Register a single buffer ring with kernel
static inline int buf_ring_register(struct uring *ring, void *ring_addr,
                                     u16 num_entries, u16 bgid) {
    struct io_uring_buf_reg reg;
    memset(&reg, 0, sizeof(reg));
    reg.ring_addr = (uint64_t)ring_addr;
    reg.ring_entries = num_entries;
    reg.bgid = bgid;
    return io_uring_register(ring->ring_fd, IORING_REGISTER_PBUF_RING, &reg, 1);
}

// Unregister a single buffer ring from kernel
static inline int buf_ring_unregister(struct uring *ring, u16 bgid) {
    struct io_uring_buf_reg reg = { .bgid = bgid };
    return io_uring_register(ring->ring_fd, IORING_UNREGISTER_PBUF_RING, &reg, 1);
}

// Initialize buffer ring manager with coalesced allocation for all groups
static int buf_ring_mgr_init(struct uring *ring, struct buf_ring_mgr *mgr,
                              const struct buf_ring_config *configs,
                              u8 num_configs) {
    if (num_configs > BUF_RING_MAX_GROUPS)
        return -EINVAL;

    memset(mgr, 0, sizeof(*mgr));

    // Calculate total size needed for all groups
    size_t total = 0;
    for (int i = 0; i < num_configs; i++) {
        if (configs[i].num_buffers > BUF_RING_MAX_BUFFERS)
            return -EINVAL;
        if ((configs[i].num_buffers & (configs[i].num_buffers - 1)) != 0)
            return -EINVAL;  // Must be power of 2
        total += sizeof(struct io_uring_buf) * configs[i].num_buffers;
        total += (size_t)configs[i].buffer_size * configs[i].num_buffers;
    }

    // Attempt mmap with huge pages
    void *ptr = mmap(NULL, total, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
    if (ptr == MAP_FAILED) {
        LOG_WARN("huge pages unavailable for buf_ring_mgr, falling back");
        ptr = mmap(NULL, total, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
        if (ptr == MAP_FAILED)
            return -errno;
    }

    mgr->base = ptr;
    mgr->total_size = total;

    // Layout groups sequentially
    size_t offset = 0;
    for (int i = 0; i < num_configs; i++) {
        struct buf_ring_group *g = &mgr->groups[i];
        size_t ring_size = sizeof(struct io_uring_buf) * configs[i].num_buffers;
        size_t data_size = (size_t)configs[i].buffer_size * configs[i].num_buffers;

        g->ring_offset = (u32)offset;
        g->data_offset = (u32)(offset + ring_size);
        g->num_buffers = configs[i].num_buffers;
        g->buffer_size = configs[i].buffer_size;
        g->buffer_shift = configs[i].buffer_shift;
        g->bgid = configs[i].bgid;
        g->mask = configs[i].num_buffers - 1;
        g->tail = 0;

        // Register this group with kernel
        int ret = buf_ring_register(ring, (char*)ptr + g->ring_offset,
                                     g->num_buffers, g->bgid);
        if (ret < 0) {
            // Cleanup already registered groups 
            for (int j = 0; j < i; j++)
                buf_ring_unregister(ring, mgr->groups[j].bgid);
            munmap(ptr, total);
            mgr->base = NULL;
            return ret;
        }

#ifdef ENABLE_ZC
        if (configs[i].is_zc) {
            g->is_zc = 1;
            g->free_count = g->num_buffers;
            memset(g->free_bitmap, 0xFF, sizeof(g->free_bitmap));
            // Clear trailing bits if not power-of-64 aligned
            u16 trailing = g->num_buffers & 63;
            if (trailing)
                g->free_bitmap[(g->num_buffers - 1) >> 6] &= (1ULL << trailing) - 1;
        } else
#endif
        {
            // Init buffers for recv mode (pre-fill ring)
            struct io_uring_buf_ring *br = BUF_RING_PTR(mgr, g);
            for (u32 j = 0; j < g->num_buffers; j++) {
                struct io_uring_buf *buf = &br->bufs[g->tail & g->mask];
                buf->addr = (uint64_t)BUF_RING_ADDR(mgr, g, j);
                buf->len = g->buffer_size;
                buf->bid = (u16)j;
                g->tail++;
            }
            smp_store_release(&br->tail, g->tail);
        }

        offset += ring_size + data_size;
    }

    mgr->num_groups = num_configs;
    return 0;
}

// Cleanup - single munmap for all groups
static inline void buf_ring_mgr_destroy(struct uring *ring,
                                         struct buf_ring_mgr *mgr) {
    for (int i = 0; i < mgr->num_groups; i++) {
        buf_ring_unregister(ring, mgr->groups[i].bgid);
    }
    if (mgr->base) {
        munmap(mgr->base, mgr->total_size);
        mgr->base = NULL;
    }
    mgr->num_groups = 0;
}

// Sync buffer ring tail to kernel
static inline void buf_ring_mgr_sync(struct buf_ring_mgr *mgr,
                                      struct buf_ring_group *g) {
    struct io_uring_buf_ring *br = BUF_RING_PTR(mgr, g);
    smp_store_release(&br->tail, g->tail);
}

// Zerocopy buffer operations
#ifdef ENABLE_ZC

// Bitmap operations
#define zc_bitmap_set(bitmap, idx) (bitmap)[(idx) >> 6] |= (1ULL << ((idx) & 63))
#define zc_bitmap_clear(bitmap, idx) (bitmap)[(idx) >> 6] &= ~(1ULL << ((idx) & 63))
#define zc_bitmap_test(bitmap, idx) (((bitmap)[(idx) >> 6] >> ((idx) & 63)) & 1)

static inline int zc_bitmap_ffs(const uint64_t *bitmap, u16 count) {
    u16 words = (count + 63) / 64;
    for (u16 i = 0; i < words; i++) {
        if (bitmap[i]) {
            u16 idx = (i << 6) + __builtin_ctzll(bitmap[i]);
            return (idx < count) ? idx : -1;
        }
    }
    return -1;
}

// Allocate a buffer from ZC group (bitmap-based)
static inline u16 buf_ring_zc_alloc(struct buf_ring_group *g) {
    if (unlikely(g->free_count == 0))
        return UINT16_MAX;

    int idx = zc_bitmap_ffs(g->free_bitmap, g->num_buffers);
    if (unlikely(idx < 0))
        return UINT16_MAX;

    zc_bitmap_clear(g->free_bitmap, (u16)idx);
    g->free_count--;
    return (u16)idx;
}

// Recycle a ZC buffer (called on notification CQE)
static inline void buf_ring_zc_recycle(struct buf_ring_group *g, u16 bid) {
    DEBUG_ONLY(if (bid > g->mask) { LOG_BUG("zc: invalid bid %u", bid); return; });
    DEBUG_ONLY(if (zc_bitmap_test(g->free_bitmap, bid)) {
        LOG_BUG("zc: double free bid %u", bid); return;
    });

    zc_bitmap_set(g->free_bitmap, bid);
    g->free_count++;
}

// Push buffer to kernel ring for bundle consumption
static inline void buf_ring_zc_push(struct buf_ring_mgr *mgr,
                                     struct buf_ring_group *g,
                                     u16 bid, u32 len) {
    struct io_uring_buf_ring *br = BUF_RING_PTR(mgr, g);
    struct io_uring_buf *buf = &br->bufs[g->tail & g->mask];
    buf->addr = (uint64_t)BUF_RING_ADDR(mgr, g, bid);
    buf->len = len;
    buf->bid = bid;
    g->tail++;
    // Caller must call buf_ring_mgr_sync() after batch
}

// Probe kernel for SEND_ZC support
static inline int buf_ring_zc_probe(struct uring *ring) {
    size_t probe_size = sizeof(struct io_uring_probe) + 256 * sizeof(struct io_uring_probe_op);

    struct io_uring_probe *probe = mmap(NULL, probe_size, PROT_READ | PROT_WRITE,
                                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (probe == MAP_FAILED)
        return -ENOMEM;

    memset(probe, 0, probe_size);
    probe->last_op = 255;

    int ret = io_uring_register(ring->ring_fd, IORING_REGISTER_PROBE, probe, 256);
    if (ret < 0) {
        munmap(probe, probe_size);
        return ret;
    }

    int supported = (probe->last_op >= IORING_OP_SEND_ZC) &&
                    (probe->ops[IORING_OP_SEND_ZC].flags & IO_URING_OP_SUPPORTED);

    munmap(probe, probe_size);
    return supported ? 0 : -EOPNOTSUPP;
}

#endif // ENABLE_ZC
