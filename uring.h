#ifndef URING_H
#define URING_H

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

/* Socket command definitions for async setsockopt (kernel 6.7+) */
#ifndef SOCKET_URING_OP_SETSOCKOPT
#define SOCKET_URING_OP_SETSOCKOPT 0
#endif

#ifndef IORING_OP_URING_CMD
#define IORING_OP_URING_CMD 46
#endif

/* ============================================================================
 * Memory barriers - x86-TSO optimized
 * On x86, loads are not reordered with other loads, stores are not reordered
 * with other stores. We only need compiler barriers + volatile for acquire/release.
 * ============================================================================ */

#if defined(__x86_64__) || defined(__i386__)
  /* x86 has strong memory model - compiler barrier is sufficient */
  #define smp_load_acquire(p) ({              \
      typeof(*(p)) ___v = *(volatile typeof(*(p)) *)(p); \
      __asm__ __volatile__("" ::: "memory");  \
      ___v;                                   \
  })
  #define smp_store_release(p, v) do {        \
      __asm__ __volatile__("" ::: "memory");  \
      *(volatile typeof(*(p)) *)(p) = (v);    \
  } while (0)
#else
  /* Generic - use full atomic fences */
  #define smp_load_acquire(p) ({                              \
      typeof(*(p)) ___v = *(volatile typeof(*(p)) *)(p);      \
      __atomic_thread_fence(__ATOMIC_ACQUIRE);                \
      ___v;                                                   \
  })
  #define smp_store_release(p, v) do {                        \
      __atomic_thread_fence(__ATOMIC_RELEASE);                \
      *(volatile typeof(*(p)) *)(p) = (v);                    \
  } while (0)
#endif

/* ============================================================================
 * Ring structures - cache-line optimized layout
 * ============================================================================ */

struct uring_sq {
    /* Kernel-shared pointers - read frequently */
    uint32_t *khead;            /* Consumer head (kernel updates) */
    uint32_t *ktail;            /* Producer tail (we update) */
    uint32_t *kring_mask;       /* Cached on init */
    uint32_t *kring_entries;    /* Cached on init */
    uint32_t *array;            /* SQE index array */
    struct io_uring_sqe *sqes;  /* SQE array */

    /* Local state - not shared with kernel */
    uint32_t ring_mask;         /* Cached from *kring_mask */
    uint32_t ring_entries;      /* Cached from *kring_entries */
    uint32_t sqe_head;          /* Our head for tracking submissions */
    uint32_t sqe_tail;          /* Our tail for tracking submissions */

    /* Init-time only */
    uint32_t *kflags;
    uint32_t *kdropped;
    size_t ring_sz;
    void *ring_ptr;
};

struct uring_cq {
    /* Kernel-shared pointers */
    uint32_t *khead;            /* Consumer head (we update) */
    uint32_t *ktail;            /* Producer tail (kernel updates) */
    struct io_uring_cqe *cqes;  /* CQE array */

    /* Cached values */
    uint32_t ring_mask;

    /* Init-time only */
    uint32_t *kring_mask;
    uint32_t *kring_entries;
    uint32_t *kflags;
    uint32_t *koverflow;
    size_t ring_sz;
    void *ring_ptr;
};

struct uring {
    struct uring_sq sq;
    struct uring_cq cq;
    int ring_fd;
    uint32_t features;
};

/* Provided buffer ring - optimized layout */
struct buf_ring {
    struct io_uring_buf_ring *br;
    uint8_t *buf_base;
    uint16_t tail;
    uint16_t mask;              /* NUM_BUFFERS - 1, cached */
};

/* ============================================================================
 * io_uring syscall wrappers (no liburing)
 * ============================================================================ */

static inline int io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

static inline int io_uring_register(int fd, unsigned opcode, void *arg, unsigned nr_args) {
    return (int)syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

/* ============================================================================
 * io_uring initialization
 * ============================================================================ */

static int uring_mmap(struct uring *ring, struct io_uring_params *p) {
    struct uring_sq *sq = &ring->sq;
    struct uring_cq *cq = &ring->cq;
    size_t size;
    int ret;

    /* SQ ring mapping */
    size = p->sq_off.array + p->sq_entries * sizeof(uint32_t);
    sq->ring_sz = size;
    sq->ring_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, ring->ring_fd,
                        IORING_OFF_SQ_RING);
    if (unlikely(sq->ring_ptr == MAP_FAILED))
        return -errno;

    /* CQ ring mapping */
    if (p->features & IORING_FEAT_SINGLE_MMAP) {
        cq->ring_ptr = sq->ring_ptr;
        cq->ring_sz = 0;
    } else {
        size = p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe);
        cq->ring_sz = size;
        cq->ring_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_POPULATE, ring->ring_fd,
                            IORING_OFF_CQ_RING);
        if (unlikely(cq->ring_ptr == MAP_FAILED)) {
            ret = -errno;
            munmap(sq->ring_ptr, sq->ring_sz);
            return ret;
        }
    }

    /* SQE array mapping */
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

    /* Setup SQ pointers */
    sq->khead = sq->ring_ptr + p->sq_off.head;
    sq->ktail = sq->ring_ptr + p->sq_off.tail;
    sq->kring_mask = sq->ring_ptr + p->sq_off.ring_mask;
    sq->kring_entries = sq->ring_ptr + p->sq_off.ring_entries;
    sq->kflags = sq->ring_ptr + p->sq_off.flags;
    sq->kdropped = sq->ring_ptr + p->sq_off.dropped;
    sq->array = sq->ring_ptr + p->sq_off.array;

    /* Cache frequently-used values */
    sq->ring_mask = *sq->kring_mask;
    sq->ring_entries = *sq->kring_entries;

    /* Setup CQ pointers */
    cq->khead = cq->ring_ptr + p->cq_off.head;
    cq->ktail = cq->ring_ptr + p->cq_off.tail;
    cq->kring_mask = cq->ring_ptr + p->cq_off.ring_mask;
    cq->kring_entries = cq->ring_ptr + p->cq_off.ring_entries;
    cq->kflags = cq->ring_ptr + p->cq_off.flags;
    cq->koverflow = cq->ring_ptr + p->cq_off.overflow;
    cq->cqes = cq->ring_ptr + p->cq_off.cqes;

    /* Cache ring mask */
    cq->ring_mask = *cq->kring_mask;

    return 0;
}

static int uring_init(struct uring *ring) {
    struct io_uring_params p;
    int ret;

    memset(&p, 0, sizeof(p));
    memset(ring, 0, sizeof(*ring));

    p.flags = IORING_SETUP_SUBMIT_ALL |
              IORING_SETUP_SINGLE_ISSUER |
              IORING_SETUP_DEFER_TASKRUN |
              IORING_SETUP_COOP_TASKRUN |
              IORING_SETUP_CQSIZE;
    p.cq_entries = CQ_ENTRIES;

    ring->ring_fd = io_uring_setup(SQ_ENTRIES, &p);
    if (unlikely(ring->ring_fd < 0))
        return -errno;

    ring->features = p.features;

    ret = uring_mmap(ring, &p);
    if (unlikely(ret < 0)) {
        close(ring->ring_fd);
        return ret;
    }

    return 0;
}

/* ============================================================================
 * SQE acquisition - OPTIMIZED: no memset, minimal work
 * ============================================================================ */

static inline struct io_uring_sqe *uring_get_sqe(struct uring *ring) {
    struct uring_sq *sq = &ring->sq;
    uint32_t head = smp_load_acquire(sq->khead);
    uint32_t next = sq->sqe_tail + 1;

    /* Check if SQ is full */
    if (unlikely(next - head > sq->ring_entries))
        return NULL;

    struct io_uring_sqe *sqe = &sq->sqes[sq->sqe_tail & sq->ring_mask];
    sq->sqe_tail = next;

    /* NO MEMSET - caller must initialize all required fields */
    return sqe;
}

static inline int uring_submit(struct uring *ring) {
    struct uring_sq *sq = &ring->sq;
    uint32_t to_submit = sq->sqe_tail - sq->sqe_head;

    if (!to_submit)
        return 0;

    /* Fill SQ array with SQE indices */
    uint32_t mask = sq->ring_mask;
    uint32_t ktail = *sq->ktail;
    uint32_t i = sq->sqe_head;

    /* Unrolled loop for common case */
    while (i != sq->sqe_tail) {
        sq->array[ktail & mask] = i & mask;
        ktail++;
        i++;
    }

    smp_store_release(sq->ktail, ktail);
    sq->sqe_head = sq->sqe_tail;

    return (int)to_submit;
}

static inline int uring_submit_and_wait(struct uring *ring,
                                         unsigned wait_nr,
                                         struct __kernel_timespec *ts) {
    int to_submit = uring_submit(ring);
    unsigned flags = IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG;

    /* Zero-initialize to avoid kernel reading garbage padding */
    struct io_uring_getevents_arg arg;
    memset(&arg, 0, sizeof(arg));
    arg.sigmask_sz = _NSIG / 8;
    arg.ts = (uint64_t)ts;

    long ret = syscall(__NR_io_uring_enter, ring->ring_fd, to_submit, wait_nr,
                       flags, &arg, sizeof(arg));

    if (unlikely(ret < 0)) {
        ret = -errno;
        if (ret != -ETIME && ret != -EINTR)
            return (int)ret;
    }

    return to_submit;
}

/* ============================================================================
 * Provided buffer ring
 * ============================================================================ */

static int buf_ring_init(struct uring *ring, struct buf_ring *br) {
    size_t ring_entries_size = sizeof(struct io_uring_buf) * NUM_BUFFERS;
    size_t buffers_size = (size_t)BUFFER_SIZE * NUM_BUFFERS;
    size_t total_size = ring_entries_size + buffers_size;

    /* Try huge pages first */
    void *ptr = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
    if (ptr == MAP_FAILED) {
        LOG_WARN("huge pages unavailable, falling back to regular pages");
        ptr = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
        if (unlikely(ptr == MAP_FAILED))
            return -errno;
    }

    br->br = ptr;
    br->buf_base = (uint8_t *)ptr + ring_entries_size;
    br->tail = 0;
    br->mask = NUM_BUFFERS - 1;

    /* Initialize buffer entries using pointer arithmetic (no multiplication) */
    uint8_t *buf_ptr = br->buf_base;
    for (uint32_t i = 0; i < NUM_BUFFERS; i++) {
        struct io_uring_buf *buf = &br->br->bufs[br->tail & br->mask];
        buf->addr = (uint64_t)buf_ptr;
        buf->len = BUFFER_SIZE;
        buf->bid = (uint16_t)i;
        br->tail++;
        buf_ptr += BUFFER_SIZE;
    }
    smp_store_release(&br->br->tail, br->tail);

    struct io_uring_buf_reg reg;
    memset(&reg, 0, sizeof(reg));
    reg.ring_addr = (uint64_t)br->br;
    reg.ring_entries = NUM_BUFFERS;
    reg.bgid = BUFFER_GROUP_ID;

    int ret = io_uring_register(ring->ring_fd, IORING_REGISTER_PBUF_RING, &reg, 1);
    if (unlikely(ret < 0))
        return ret;

    return 0;
}

/* Hot path - inline, no validation in production */
static inline void buf_ring_recycle(struct buf_ring *br, uint16_t bid) {
    DEBUG_ONLY(if (bid > br->mask) { LOG_BUG("invalid bid %u", bid); return; });

    uint16_t tail = br->tail;
    struct io_uring_buf *buf = &br->br->bufs[tail & br->mask];

    /* Use shift instead of multiply */
    buf->addr = (uint64_t)(br->buf_base + ((uint32_t)bid << BUFFER_SHIFT));
    buf->len = BUFFER_SIZE;
    buf->bid = bid;

    br->tail = tail + 1;
    smp_store_release(&br->br->tail, br->tail);
}

#endif /* URING_H */
