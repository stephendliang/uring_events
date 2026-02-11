#pragma once

#include "core.h"
#include "util.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>  // for offsetof

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

// Zero-copy recv constants (kernel 6.12+)
#ifndef IORING_SETUP_CQE32
#define IORING_SETUP_CQE32       (1U << 11)
#endif
#ifndef IORING_SETUP_CQE_MIXED
#define IORING_SETUP_CQE_MIXED   (1U << 18)
#endif
#ifndef IORING_OP_RECV_ZC
#define IORING_OP_RECV_ZC        64
#endif
#ifndef IORING_REGISTER_ZCRX_IFQ
#define IORING_REGISTER_ZCRX_IFQ 32
#endif
#ifndef IORING_ZCRX_AREA_SHIFT
#define IORING_ZCRX_AREA_SHIFT   48
#endif
#ifndef IORING_ZCRX_AREA_MASK
#define IORING_ZCRX_AREA_MASK    (~(((__u64)1 << IORING_ZCRX_AREA_SHIFT) - 1))
#endif
#ifndef IORING_MEM_REGION_TYPE_USER
#define IORING_MEM_REGION_TYPE_USER 1
#endif

// Ring fd registration (kernel 6.4+)
#ifndef IORING_REGISTER_RING_FDS
#define IORING_REGISTER_RING_FDS 20
#endif

#ifndef IORING_UNREGISTER_RING_FDS
#define IORING_UNREGISTER_RING_FDS 21
#endif

#ifndef IORING_ENTER_REGISTERED_RING
#define IORING_ENTER_REGISTERED_RING (1U << 4)
#endif

// Sparse file registration (kernel 5.19+)
#ifndef IORING_REGISTER_FILES2
#define IORING_REGISTER_FILES2 13
#endif

#ifndef IORING_RSRC_REGISTER_SPARSE
#define IORING_RSRC_REGISTER_SPARSE (1U << 0)
#endif

// Buffer ring configuration limits
enum {
    BUF_RING_MAX_GROUPS  = 2,   // recv + ZC only
    BUF_RING_MAX_BUFFERS = 8192,
};

// Memory barriers — compiler intrinsics handle per-arch semantics:
// x86-TSO: plain mov + compiler barrier. ARM/RISC-V: ldar/stlr or fence.
#define smp_load_acquire(p)     __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define smp_store_release(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)

// Ring structures - cache-line optimized layout
struct uring_sq {
    // === First cache line (64 bytes): Hot path ===
    u32 *khead;                     // +0:  Consumer head (kernel updates)
    u32 *ktail;                     // +8:  Producer tail (we update)
    struct io_uring_sqe *sqes;      // +16: SQE array
    u32 *array;                     // +24: SQE index array
    u32 ring_mask;                  // +32: Cached from *kring_mask
    u32 ring_entries;               // +36: Cached from *kring_entries
    u32 sqe_head;                   // +40: Our head for tracking submissions
    u32 sqe_tail;                   // +44: Our tail for tracking submissions
    u32 cached_khead;               // +48: Cached kernel head - avoid repeated loads
    u32 _pad0;                      // +52: Explicit padding
    u32 *kflags;                    // +56: Moved to first cache line

    // === Second cache line: Cold ===
    u32 *kdropped;                  // +64
    u32 *kring_mask;                // +72
    u32 *kring_entries;             // +80
    size_t ring_sz;                 // +88
    u8 *ring_ptr;                   // +96
};
// Total: 104 bytes (hole explicit, kflags moved to first cache line)

struct uring_cq {
    // === Hot path (first 32 bytes) ===
    u32 *khead;                     // +0:  Updated every CQ drain
    u32 *ktail;                     // +8:  Loaded every loop
    struct io_uring_cqe *cqes;      // +16: Indexed every CQE
    u32 ring_mask;                  // +24: Used every CQE index
    u8  cqe_shift;                  // +28: 4 for 16B CQEs, 5 for 32B CQE slots
    u8  _pad0[3];                   // +29: Explicit padding

    // === Cold init-time (remaining 48 bytes) ===
    u32 *kring_mask;                // +32
    u32 *kring_entries;             // +40
    u32 *kflags;                    // +48
    u32 *koverflow;                 // +56
    size_t ring_sz;                 // +64
    u8 *ring_ptr;                   // +72
};
// Total: 80 bytes (hole now explicit padding)

struct uring {
    struct uring_sq sq;
    struct uring_cq cq;
    int ring_fd;
    int registered_index;   // IORING_REGISTER_RING_FDS index, or -1 if unregistered
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
    u32 flags;             // Bit 0: is_zc, bits 1-31: reserved
};

// buf_ring_config flag accessors
#define BRC_FLAG_ZC  (1U << 0)
#define brc_is_zc(c) ((c)->flags & BRC_FLAG_ZC)

// Per-group descriptor - offsets into shared allocation
// Layout optimized for cache behavior: hot fields first, cold fields last
// Aggressively shrunk: bgid derived from index, num_buffers from mask+1, is_zc from bitmap
struct buf_ring_group {
    // === Hot path (first 8 bytes) ===
    u16 tail;              // +0:  Updated every recycle
    u16 mask;              // +2:  Read every recycle (num_buffers = mask + 1)
    u16 free_count;        // +4:  ZC: updated per alloc/free
    u16 free_summary;      // +6:  ZC: bitmap summary

    // === Address calculation (next 8 bytes) ===
    u32 buffer_shift;      // +8:  HOT: used in BUF_RING_ADDR
    u32 buffer_size;       // +12: WARM: occasional reads

    // === Cold offsets (next 8 bytes) ===
    u32 ring_offset;       // +16: Init-time only
    u32 data_offset;       // +20: Init-time only

    // === Pointer (final 8 bytes) ===
    u64 *free_bitmap;      // +24: ZC only (NULL = not ZC)
};
// Total: 32 bytes (fits in half cache line)
// Derived fields:
//   bgid = array index in buf_ring_mgr.groups[]
//   num_buffers = mask + 1
//   is_zc = (free_bitmap != NULL)

// buf_ring_group derived field accessors
#define BRG_IS_ZC(g)         ((g)->free_bitmap != NULL)
#define BRG_NUM_BUFFERS(g)   ((u16)((g)->mask + 1))

// Unified buffer ring manager - single mmap for all groups
struct buf_ring_mgr {
    void *base;                             // +0:  Single mmap base address
    size_t total_size;                      // +8:  Total mmap size
    struct buf_ring_group groups[BUF_RING_MAX_GROUPS]; // +16: 64 bytes (2 groups @ 32 each)
    struct {
        u8 num_groups : 2;                  // Max 2 groups
        u8 initialized : 1;                 // Manager fully initialized
        u8 _reserved : 5;                   // Future flags
    } meta;                                 // +80: 1 byte
    u8 _pad[7];                             // +81: Padding to 88 bytes
};
// Total: 88 bytes (shrunk from 104)

// Zero-copy recv context — NIC DMAs packet data directly into userspace area
struct zcrx_ctx {
    // === Hot path (first 32 bytes): refill ring ===
    u32 *rq_head;                       // +0:  kernel updates
    u32 *rq_tail;                       // +8:  we update
    struct io_uring_zcrx_rqe *rqes;     // +16
    u32 rq_tail_cached;                 // +24: batched local tail
    u32 rq_mask;                        // +28: rq_entries - 1

    // === Address calc (next 16 bytes) ===
    u8  *area;                          // +32: zero-copy area base
    u64 area_token;                     // +40: from kernel, for refill offset

    // === Cold (next 24 bytes) ===
    u64 area_size;                      // +48: for munmap
    void *rq_ring_ptr;                  // +56: for munmap
    u64 rq_ring_size;                   // +64: for munmap
    u32 rq_entries;                     // +72
    u32 zcrx_id;                        // +76
    u32 if_idx;                         // +80
    u32 if_rxq;                         // +84
    u8  enabled;                        // +88
    u8  _pad[7];                        // +89-95
};
// Total: 96 bytes

// Legacy single-group struct for backwards compatibility
struct buf_ring {
    struct io_uring_buf_ring *br;
    u8 *buf_base;
    u16 tail;
    u16 mask;              // num_buffers - 1, cached
    u32 buffer_size;
    u32 buffer_shift;
};

// Layout verification - prevent silent ABI breaks
_Static_assert(sizeof(struct buf_ring_config) == 16,
               "buf_ring_config layout changed");
_Static_assert(sizeof(struct buf_ring) == 32,
               "buf_ring layout changed");
_Static_assert(sizeof(struct buf_ring_group) == 32,
               "buf_ring_group layout changed");
_Static_assert(sizeof(struct uring_cq) == 80,
               "uring_cq layout changed");
_Static_assert(sizeof(struct uring_sq) == 104,
               "uring_sq layout changed");
_Static_assert(sizeof(struct buf_ring_mgr) == 88,
               "buf_ring_mgr layout changed");
_Static_assert(sizeof(struct zcrx_ctx) == 96,
               "zcrx_ctx layout changed");

// Hot field offset verification
_Static_assert(offsetof(struct buf_ring_group, tail) == 0,
               "buf_ring_group.tail must be at offset 0");
_Static_assert(offsetof(struct uring_cq, ring_mask) < 32,
               "uring_cq.ring_mask must be in first 32 bytes");

// Buffer ring accessor macros - fast, no function call overhead
#define BUF_RING_PTR(mgr, grp) \
    ((struct io_uring_buf_ring *)((char*)(mgr)->base + (grp)->ring_offset))

#define BUF_RING_DATA(mgr, grp) \
    ((u8 *)((char*)(mgr)->base + (grp)->data_offset))

#define BUF_RING_ADDR(mgr, grp, idx) \
    (BUF_RING_DATA(mgr, grp) + ((u32)(idx) << (grp)->buffer_shift))

// syscall wrappers; no liburing
#define io_uring_setup(entries, params) \
    sys_io_uring_setup((entries), (params))
#define io_uring_register(fd, opcode, arg, nr_args) \
    sys_io_uring_register((fd), (opcode), (arg), (nr_args))

// mmap error checking — raw syscalls return negative errno in pointer
#define IS_MMAP_ERR(p) ((unsigned long)(p) >= (unsigned long)-4095UL)
#define MMAP_ERR(p)    ((int)(long)(p))

// Cold-path functions — implementations in uring.c
int uring_init(struct uring *ring, u32 sq_entries, u32 cq_entries);
int uring_register_fixed_files(struct uring *ring, u32 count);
int buf_ring_mgr_init(struct uring *ring, struct buf_ring_mgr *mgr,
                       const struct buf_ring_config *configs, u8 num_configs);
void buf_ring_mgr_destroy(struct uring *ring, struct buf_ring_mgr *mgr);
int buf_ring_zc_probe(struct uring *ring);

// Zero-copy recv — cold-path registration/teardown
int  zcrx_probe(struct uring *ring);
int  zcrx_init(struct uring *ring, struct zcrx_ctx *zcrx,
               u32 if_idx, u32 if_rxq, u64 area_size, u32 rq_entries);
void zcrx_destroy(struct uring *ring, struct zcrx_ctx *zcrx);

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

// O(1) submit - relies on identity mapping array[n] = n pre-filled at init.
// Invariant: ktail == sqe_head at entry (SINGLE_ISSUER + sequential alloc).
// Requirements: SINGLE_ISSUER, sequential allocation, contiguous submission.
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

    // Pre-zeroed template avoids memset on every iteration.
    // Only sigmask_sz and ts need values; rest must be 0 for kernel.
    struct io_uring_getevents_arg arg = {
        .sigmask_sz = _NSIG / 8,
        .ts = (u64)ts,
    };

    // Use registered ring fd index if available — skips fd→file lookup
    // in kernel (~40-60 cycles saved per syscall)
    int enter_fd = ring->ring_fd;
    if (ring->registered_index >= 0) {
        enter_fd = ring->registered_index;
        flags |= IORING_ENTER_REGISTERED_RING;
    }

    long ret = sys_io_uring_enter(enter_fd, to_submit, wait_nr,
                                   flags, &arg, sizeof(arg));

    if (unlikely(ret < 0)) {
        if (ret != -ETIME && ret != -EINTR)
            return (int)ret;
    }

    return to_submit;
}

// Hot path - inline, no validation in production
// IMPORTANT: Does NOT issue memory barrier. Caller MUST call buf_ring_sync()
// after batching recycles to make buffers visible to kernel.
static inline void buf_ring_recycle(struct buf_ring *br, u16 bid) {
    DEBUG_ONLY(if (bid > br->mask) { LOG_BUG("invalid bid %u", bid); return; });

    u16 tail = br->tail;
    struct io_uring_buf *buf = &br->br->bufs[tail & br->mask];

    buf->addr = (u64)(br->buf_base + ((u32)bid << br->buffer_shift));
    buf->len = br->buffer_size;
    buf->bid = bid;

    br->tail = tail + 1;
    // NO barrier - call buf_ring_sync() after batch
}

// Publish recycled buffers to kernel. Call once after batch of buf_ring_recycle()
static inline void buf_ring_sync(struct buf_ring *br) {
    smp_store_release(&br->br->tail, br->tail);
}

// Sync buffer ring tail to kernel
static inline void buf_ring_mgr_sync(struct buf_ring_mgr *mgr,
                                      struct buf_ring_group *g) {
    struct io_uring_buf_ring *br = BUF_RING_PTR(mgr, g);
    smp_store_release(&br->tail, g->tail);
}

// Zerocopy buffer operations

// Bitmap operations with hierarchical summary for O(1) lookup

// Set bit (mark buffer as free) - updates summary if word becomes non-zero
static inline void zc_bitmap_set(struct buf_ring_group *g, u16 idx) {
    u16 word = idx >> 6;
    u64 old = g->free_bitmap[word];
    g->free_bitmap[word] = old | (1ULL << (idx & 63));
    // Update summary: if word was zero, now has free slots
    if (old == 0)
        g->free_summary |= (1U << word);
}

// Clear bit (mark buffer as in-flight) - updates summary if word becomes zero
static inline void zc_bitmap_clear(struct buf_ring_group *g, u16 idx) {
    u16 word = idx >> 6;
    u64 new_val = g->free_bitmap[word] & ~(1ULL << (idx & 63));
    g->free_bitmap[word] = new_val;
    // Update summary: if word is now zero, no free slots in this word
    if (new_val == 0)
        g->free_summary &= ~(1U << word);
}

static inline int zc_bitmap_test(const struct buf_ring_group *g, u16 idx) {
    return (g->free_bitmap[idx >> 6] >> (idx & 63)) & 1;
}

// O(1) find-first-set using hierarchical summary
static inline int zc_bitmap_ffs(const struct buf_ring_group *g) {
    if (g->free_summary == 0)
        return -1;
    // Find first word with free slots
    u16 word = (u16)__builtin_ctz(g->free_summary);
    u64 bits = g->free_bitmap[word];
    if (bits == 0)
        return -1;  // Should not happen if summary is correct
    u16 idx = (word << 6) + (u16)__builtin_ctzll(bits);
    return (idx < BRG_NUM_BUFFERS(g)) ? idx : -1;
}

// Allocate a buffer from ZC group (bitmap-based)
static inline u16 buf_ring_zc_alloc(struct buf_ring_group *g) {
    if (unlikely(g->free_count == 0))
        return UINT16_MAX;

    int idx = zc_bitmap_ffs(g);
    if (unlikely(idx < 0))
        return UINT16_MAX;

    zc_bitmap_clear(g, (u16)idx);
    g->free_count--;
    return (u16)idx;
}

// Recycle a ZC buffer (called on notification CQE)
static inline void buf_ring_zc_recycle(struct buf_ring_group *g, u16 bid) {
    DEBUG_ONLY(if (bid > g->mask) { LOG_BUG("zc: invalid bid %u", bid); return; });
    DEBUG_ONLY(if (zc_bitmap_test(g, bid)) {
        LOG_BUG("zc: double free bid %u", bid); return;
    });

    zc_bitmap_set(g, bid);
    g->free_count++;
}

// Push buffer to kernel ring for bundle consumption
static inline void buf_ring_zc_push(struct buf_ring_mgr *mgr,
                                     struct buf_ring_group *g,
                                     u16 bid, u32 len) {
    struct io_uring_buf_ring *br = BUF_RING_PTR(mgr, g);
    struct io_uring_buf *buf = &br->bufs[g->tail & g->mask];
    buf->addr = (u64)BUF_RING_ADDR(mgr, g, bid);
    buf->len = len;
    buf->bid = bid;
    g->tail++;
    // Caller must call buf_ring_mgr_sync() after batch
}

// Zero-copy recv hot-path inlines

// Return buffer to kernel. No barrier — call zcrx_refill_sync() after batch.
static inline void zcrx_refill(struct zcrx_ctx *zcrx, u64 area_off, u32 len) {
    u32 tail = zcrx->rq_tail_cached;
    struct io_uring_zcrx_rqe *rqe = &zcrx->rqes[tail & zcrx->rq_mask];
    rqe->off = ((u64)zcrx->area_token << IORING_ZCRX_AREA_SHIFT) | area_off;
    rqe->len = len;
    zcrx->rq_tail_cached = tail + 1;
}

// Publish refill ring tail. Call once after batch.
static inline void zcrx_refill_sync(struct zcrx_ctx *zcrx) {
    smp_store_release(zcrx->rq_tail, zcrx->rq_tail_cached);
}

// Extract data pointer from zcrx CQE offset.
static inline const u8 *zcrx_data(const struct zcrx_ctx *zcrx, u64 zcqe_off) {
    return zcrx->area + (zcqe_off & ~IORING_ZCRX_AREA_MASK);
}

