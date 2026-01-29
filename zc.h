#ifndef ZC_H
#define ZC_H

/*
 * Zerocopy + Bundle Send Support for io_uring
 *
 * Requires: uring.h included first
 * Kernel: 6.10+ (IORING_RECVSEND_BUNDLE)
 *
 * Key difference from recv buffer ring:
 *   - Recv: kernel fills buffer, user recycles by re-adding to ring
 *   - Send ZC: user fills buffer, kernel consumes, user tracks via bitmap
 *              until notification CQE confirms buffer is safe to reuse
 */

/* ============================================================================
 * Kernel constants - define if not present in headers
 * ============================================================================ */

#ifndef IORING_OP_SEND_ZC
#define IORING_OP_SEND_ZC 53
#endif

#ifndef IORING_RECVSEND_BUNDLE
#define IORING_RECVSEND_BUNDLE (1U << 1)
#endif

#ifndef IORING_CQE_F_NOTIF
#define IORING_CQE_F_NOTIF (1U << 3)
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

#ifndef ZC_NUM_BUFFERS
#define ZC_NUM_BUFFERS      1024
#endif

#ifndef ZC_BUFFER_SIZE
#define ZC_BUFFER_SIZE      4096
#endif

#ifndef ZC_BUFFER_SHIFT
#define ZC_BUFFER_SHIFT     12  /* log2(ZC_BUFFER_SIZE) */
#endif

#ifndef ZC_BUFFER_GROUP_ID
#define ZC_BUFFER_GROUP_ID  1   /* Distinct from recv buffer group */
#endif

_Static_assert((ZC_NUM_BUFFERS & (ZC_NUM_BUFFERS - 1)) == 0,
               "ZC_NUM_BUFFERS must be power of 2");
_Static_assert(ZC_NUM_BUFFERS <= 32768,
               "ZC_NUM_BUFFERS max is 32768");
_Static_assert((1 << ZC_BUFFER_SHIFT) == ZC_BUFFER_SIZE,
               "ZC_BUFFER_SHIFT must match ZC_BUFFER_SIZE");

/* ============================================================================
 * Operation type - integrator must add to event.c BEFORE including zc.h:
 *
 *   1. Add to enum op_type:
 *        OP_SEND_ZC = 5,
 *
 *   2. Add after the enum:
 *        #define OP_SEND_ZC_SHIFTED ((uint64_t)OP_SEND_ZC << 32)
 * ============================================================================ */

#ifndef OP_SEND_ZC_SHIFTED
#error "OP_SEND_ZC_SHIFTED must be defined before including zc.h"
#endif

/* ============================================================================
 * Zerocopy send buffer ring
 *
 * Extends concept from buf_ring (uring.h) with bitmap tracking for in-flight
 * buffers. ZC buffers can't be recycled until notification CQE arrives.
 * ============================================================================ */

struct zc_buf_ring {
    struct io_uring_buf_ring *br;
    uint8_t *buf_base;
    uint16_t tail;
    uint16_t mask;

    /* ZC-specific: track in-flight buffers (1 = free, 0 = in-flight) */
    uint64_t free_bitmap[(ZC_NUM_BUFFERS + 63) / 64];
    uint16_t free_count;
};

/* ============================================================================
 * SQE Template - Zerocopy Bundle Send
 * ============================================================================ */

__attribute__((aligned(64)))
static const struct io_uring_sqe ZC_SQE_TEMPLATE_SEND = {
    .opcode = IORING_OP_SEND_ZC,
    .flags = IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT,
    .ioprio = IORING_RECVSEND_BUNDLE,
    .fd = 0,
    .off = 0,
    .addr = 0,
    .len = 0,
    .msg_flags = 0,
    .user_data = 0,
    .buf_group = ZC_BUFFER_GROUP_ID,
    .personality = 0,
    .splice_fd_in = 0,
    .addr3 = 0,
    .__pad2 = {0},
};

/* ============================================================================
 * Bitmap operations
 * ============================================================================ */

static inline void zc_bitmap_set(uint64_t *bitmap, uint16_t idx) {
    bitmap[idx >> 6] |= (1ULL << (idx & 63));
}

static inline void zc_bitmap_clear(uint64_t *bitmap, uint16_t idx) {
    bitmap[idx >> 6] &= ~(1ULL << (idx & 63));
}

static inline int zc_bitmap_test(const uint64_t *bitmap, uint16_t idx) {
    return (bitmap[idx >> 6] >> (idx & 63)) & 1;
}

static inline int zc_bitmap_ffs(const uint64_t *bitmap, uint16_t count) {
    uint16_t words = (count + 63) / 64;
    for (uint16_t i = 0; i < words; i++) {
        if (bitmap[i]) {
            int bit = __builtin_ctzll(bitmap[i]);
            uint16_t idx = (i << 6) + bit;
            return (idx < count) ? idx : -1;
        }
    }
    return -1;
}

/* ============================================================================
 * Buffer ring init - similar to buf_ring_init but with bitmap
 * ============================================================================ */

static int zc_buf_ring_init(struct uring *ring, struct zc_buf_ring *zbr) {
    size_t ring_size = sizeof(struct io_uring_buf) * ZC_NUM_BUFFERS;
    size_t bufs_size = (size_t)ZC_BUFFER_SIZE * ZC_NUM_BUFFERS;
    size_t total = ring_size + bufs_size;

    /* Mmap with huge pages fallback - same pattern as buf_ring_init */
    void *ptr = mmap(NULL, total, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
    if (ptr == MAP_FAILED) {
        ptr = mmap(NULL, total, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
        if (unlikely(ptr == MAP_FAILED))
            return -errno;
    }

    zbr->br = ptr;
    zbr->buf_base = (uint8_t *)ptr + ring_size;
    zbr->tail = 0;
    zbr->mask = ZC_NUM_BUFFERS - 1;
    zbr->free_count = ZC_NUM_BUFFERS;

    /* ZC-specific: initialize bitmap (all free) */
    memset(zbr->free_bitmap, 0xFF, sizeof(zbr->free_bitmap));
    uint16_t trailing = ZC_NUM_BUFFERS & 63;
    if (trailing)
        zbr->free_bitmap[(ZC_NUM_BUFFERS - 1) >> 6] &= (1ULL << trailing) - 1;

    /* Register with kernel - same pattern as buf_ring_init */
    struct io_uring_buf_reg reg;
    memset(&reg, 0, sizeof(reg));
    reg.ring_addr = (uint64_t)zbr->br;
    reg.ring_entries = ZC_NUM_BUFFERS;
    reg.bgid = ZC_BUFFER_GROUP_ID;

    int ret = io_uring_register(ring->ring_fd, IORING_REGISTER_PBUF_RING, &reg, 1);
    if (unlikely(ret < 0)) {
        munmap(ptr, total);
        return ret;
    }

    return 0;
}

/* ============================================================================
 * Buffer management - ZC-specific (bitmap-based, not ring-based recycle)
 * ============================================================================ */

static inline uint16_t zc_buf_alloc(struct zc_buf_ring *zbr) {
    if (unlikely(zbr->free_count == 0))
        return UINT16_MAX;

    int idx = zc_bitmap_ffs(zbr->free_bitmap, ZC_NUM_BUFFERS);
    if (unlikely(idx < 0))
        return UINT16_MAX;

    zc_bitmap_clear(zbr->free_bitmap, (uint16_t)idx);
    zbr->free_count--;
    return (uint16_t)idx;
}

static inline void *zc_buf_addr(struct zc_buf_ring *zbr, uint16_t idx) {
    return zbr->buf_base + ((uint32_t)idx << ZC_BUFFER_SHIFT);
}

/* Called on notification CQE only - marks buffer as reusable */
static inline void zc_buf_recycle(struct zc_buf_ring *zbr, uint16_t buf_idx) {
    DEBUG_ONLY(if (buf_idx > zbr->mask) { LOG_BUG("zc: invalid bid %u", buf_idx); return; });
    DEBUG_ONLY(if (zc_bitmap_test(zbr->free_bitmap, buf_idx)) {
        LOG_BUG("zc: double free bid %u", buf_idx); return;
    });

    zc_bitmap_set(zbr->free_bitmap, buf_idx);
    zbr->free_count++;
}

/* Push buffer to kernel ring for bundle consumption */
static inline void zc_buf_ring_push(struct zc_buf_ring *zbr, uint16_t buf_idx,
                                     uint32_t len) {
    uint16_t tail = zbr->tail;
    struct io_uring_buf *buf = &zbr->br->bufs[tail & zbr->mask];

    buf->addr = (uint64_t)(zbr->buf_base + ((uint32_t)buf_idx << ZC_BUFFER_SHIFT));
    buf->len = len;
    buf->bid = buf_idx;
    zbr->tail = tail + 1;
    /* Caller must call smp_store_release(&zbr->br->tail, zbr->tail) after batch */
}

/* ============================================================================
 * SQE preparation - matches event.c style
 * ============================================================================ */

#ifdef USE_AVX512

static inline void prep_send_zc_direct(struct io_uring_sqe *sqe, int fd,
                                        uint16_t buf_idx) {
    __m512i zmm = _mm512_load_si512((const __m512i *)&ZC_SQE_TEMPLATE_SEND);
    zmm = _mm512_mask_set1_epi32(zmm, 1U << 1, fd);
    uint64_t ud = OP_SEND_ZC_SHIFTED | (uint32_t)fd | ((uint64_t)buf_idx << 40);
    zmm = _mm512_mask_set1_epi64(zmm, 1U << 4, (long long)ud);
    _mm512_store_si512((__m512i *)sqe, zmm);
}

#elif defined(USE_AVX2)

static inline void prep_send_zc_direct(struct io_uring_sqe *sqe, int fd,
                                        uint16_t buf_idx) {
    __m256i lo = _mm256_load_si256((const __m256i *)&ZC_SQE_TEMPLATE_SEND);
    __m256i hi = _mm256_load_si256((const __m256i *)&ZC_SQE_TEMPLATE_SEND + 1);
    lo = _mm256_blend_epi32(lo, _mm256_set1_epi32(fd), 1 << 1);
    uint64_t ud = OP_SEND_ZC_SHIFTED | (uint32_t)fd | ((uint64_t)buf_idx << 40);
    hi = _mm256_blend_epi32(hi, _mm256_set1_epi64x((long long)ud), 0x03);
    _mm256_store_si256((__m256i *)sqe, lo);
    _mm256_store_si256((__m256i *)sqe + 1, hi);
}

#else

static inline void prep_send_zc_direct(struct io_uring_sqe *sqe, int fd,
                                        uint16_t buf_idx) {
    *sqe = ZC_SQE_TEMPLATE_SEND;
    sqe->fd = fd;
    sqe->user_data = OP_SEND_ZC_SHIFTED | (uint32_t)fd | ((uint64_t)buf_idx << 40);
}

#endif

/* ============================================================================
 * High-level API - matches queue_send() pattern
 * ============================================================================ */

static inline bool queue_send_zc(struct server_ctx *ctx, int fd,
                                  const void *data, uint32_t len) {
    struct conn_state *c = get_conn(fd);
    if (unlikely(!c) || c->closing)
        return false;

    uint16_t buf_idx = zc_buf_alloc(&ctx->zc_br);
    if (unlikely(buf_idx == UINT16_MAX)) {
        LOG_WARN("zc: no buffers fd=%d", fd);
        return false;
    }

    void *buf = zc_buf_addr(&ctx->zc_br, buf_idx);
    uint32_t copy_len = (len > ZC_BUFFER_SIZE) ? ZC_BUFFER_SIZE : len;
    memcpy(buf, data, copy_len);

    zc_buf_ring_push(&ctx->zc_br, buf_idx, copy_len);
    smp_store_release(&ctx->zc_br.br->tail, ctx->zc_br.tail);

    struct io_uring_sqe *sqe = uring_get_sqe(&ctx->ring);
    if (unlikely(!sqe)) {
        LOG_ERROR("zc: SQ full fd=%d", fd);
        return false;
    }

    prep_send_zc_direct(sqe, fd, buf_idx);
    return true;
}

/* ============================================================================
 * CQE handler - two-phase: completion then notification
 * ============================================================================ */

static inline void handle_send_zc(struct server_ctx *ctx,
                                   struct io_uring_cqe *cqe, int fd) {
    uint16_t buf_idx = decode_buf_idx(cqe->user_data);

    if (cqe->flags & IORING_CQE_F_NOTIF) {
        /* Notification: buffer safe to reuse */
        zc_buf_recycle(&ctx->zc_br, buf_idx);
        return;
    }

    /* Completion: send done, buffer still in-flight to NIC */
    int res = cqe->res;
    if (unlikely(res < 0)) {
        if (res != -EPIPE && res != -ECONNRESET && res != -EBADF && res != -ECANCELED)
            LOG_ERROR("zc send error %d fd=%d", res, fd);
        queue_close(ctx, fd);
    }
    /* Do NOT recycle - wait for NOTIF */
}

/* ============================================================================
 * Feature detection
 * ============================================================================ */

static inline int zc_probe_support(struct uring *ring) {
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

/* ============================================================================
 * Cleanup
 * ============================================================================ */

static inline void zc_buf_ring_destroy(struct uring *ring, struct zc_buf_ring *zbr) {
    if (!zbr->br)
        return;

    struct io_uring_buf_reg reg = { .bgid = ZC_BUFFER_GROUP_ID };
    io_uring_register(ring->ring_fd, IORING_UNREGISTER_PBUF_RING, &reg, 1);

    size_t total = sizeof(struct io_uring_buf) * ZC_NUM_BUFFERS +
                   (size_t)ZC_BUFFER_SIZE * ZC_NUM_BUFFERS;
    munmap(zbr->br, total);
    zbr->br = NULL;
}

#endif /* ZC_H */
