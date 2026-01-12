/*
 * Raw io_uring HTTP server - No liburing, maximum performance
 *
 * Following CLAUDE.md architecture:
 * - Shared-nothing per-core isolation
 * - No liburing (direct syscalls + ring manipulation)
 * - IORING_SETUP_SUBMIT_ALL, SINGLE_ISSUER, DEFER_TASKRUN, COOP_TASKRUN
 * - Multishot accept + multishot recv with provided buffers
 * - Zero mallocs in hot path
 * - Zero context switches in steady state
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>

#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/io_uring.h>
#include <linux/time_types.h>

/* ============================================================================
 * Configuration - All tunable at compile time
 * ============================================================================ */

#define SQ_ENTRIES          2048
#define CQ_ENTRIES          (SQ_ENTRIES * 4)    /* 4x SQ per CLAUDE.md */
#define NUM_BUFFERS         4096
#define BUFFER_SIZE         2048
#define BUFFER_GROUP_ID     0
#define LISTEN_BACKLOG      4096

/* HTTP response - precomputed at compile time */
static const char HTTP_200_RESPONSE[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 2\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "OK";

#define HTTP_200_LEN (sizeof(HTTP_200_RESPONSE) - 1)

/* ============================================================================
 * io_uring syscall wrappers (no liburing)
 * ============================================================================ */

static inline int io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return syscall(__NR_io_uring_setup, entries, p);
}

static inline int io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                                  unsigned flags, sigset_t *sig) {
    return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig, _NSIG / 8);
}

static inline int io_uring_enter2(int fd, unsigned to_submit, unsigned min_complete,
                                   unsigned flags, sigset_t *sig, size_t sz) {
    return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig, sz);
}

static inline int io_uring_register(int fd, unsigned opcode, void *arg, unsigned nr_args) {
    return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

/* ============================================================================
 * Memory barriers - x86-TSO specific (acquire/release)
 * ============================================================================ */

#define smp_load_acquire(p)                                     \
    ({                                                          \
        typeof(*(p)) ___p = (*(volatile typeof(p))(p));         \
        __atomic_thread_fence(__ATOMIC_ACQUIRE);                \
        ___p;                                                   \
    })

#define smp_store_release(p, v)                                 \
    do {                                                        \
        __atomic_thread_fence(__ATOMIC_RELEASE);                \
        (*(volatile typeof(p))(p)) = (v);                       \
    } while (0)

/* ============================================================================
 * Ring structures - direct kernel interface
 * ============================================================================ */

struct uring_sq {
    uint32_t *khead;
    uint32_t *ktail;
    uint32_t *kring_mask;
    uint32_t *kring_entries;
    uint32_t *kflags;
    uint32_t *kdropped;
    uint32_t *array;
    struct io_uring_sqe *sqes;

    uint32_t sqe_head;
    uint32_t sqe_tail;
    size_t ring_sz;
    void *ring_ptr;
};

struct uring_cq {
    uint32_t *khead;
    uint32_t *ktail;
    uint32_t *kring_mask;
    uint32_t *kring_entries;
    uint32_t *kflags;
    uint32_t *koverflow;
    struct io_uring_cqe *cqes;

    size_t ring_sz;
    void *ring_ptr;
};

struct uring {
    struct uring_sq sq;
    struct uring_cq cq;
    uint32_t flags;
    int ring_fd;
    uint32_t features;
    int enter_ring_fd;
    uint32_t pad[2];
};

/* Provided buffer ring */
struct buf_ring {
    struct io_uring_buf_ring *br;
    uint8_t *buf_base;
    uint32_t buf_cnt;
    uint32_t buf_len;
    uint16_t tail;
    uint16_t bgid;
};

/* ============================================================================
 * Context encoding - pack into 64-bit user_data
 * Layout: [fd:32][op:8][buf_idx:16][flags:8]
 * ============================================================================ */

enum op_type {
    OP_ACCEPT   = 0,
    OP_RECV     = 1,
    OP_SEND     = 2,
    OP_CLOSE    = 3,
};

static inline uint64_t encode_user_data(int32_t fd, uint8_t op, uint16_t buf_idx) {
    return ((uint64_t)(uint32_t)fd) |
           ((uint64_t)op << 32) |
           ((uint64_t)buf_idx << 40);
}

static inline int32_t decode_fd(uint64_t user_data) {
    return (int32_t)(user_data & 0xFFFFFFFF);
}

static inline uint8_t decode_op(uint64_t user_data) {
    return (uint8_t)((user_data >> 32) & 0xFF);
}

static inline uint16_t decode_buf_idx(uint64_t user_data) {
    return (uint16_t)((user_data >> 40) & 0xFFFF);
}

/* ============================================================================
 * io_uring initialization - raw setup without liburing
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
    if (sq->ring_ptr == MAP_FAILED)
        return -errno;

    /* CQ ring mapping - may share with SQ or be separate */
    if (p->features & IORING_FEAT_SINGLE_MMAP) {
        cq->ring_ptr = sq->ring_ptr;
        cq->ring_sz = 0;
    } else {
        size = p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe);
        cq->ring_sz = size;
        cq->ring_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_POPULATE, ring->ring_fd,
                            IORING_OFF_CQ_RING);
        if (cq->ring_ptr == MAP_FAILED) {
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
    if (sq->sqes == MAP_FAILED) {
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

    /* Setup CQ pointers */
    cq->khead = cq->ring_ptr + p->cq_off.head;
    cq->ktail = cq->ring_ptr + p->cq_off.tail;
    cq->kring_mask = cq->ring_ptr + p->cq_off.ring_mask;
    cq->kring_entries = cq->ring_ptr + p->cq_off.ring_entries;
    cq->kflags = cq->ring_ptr + p->cq_off.flags;
    cq->koverflow = cq->ring_ptr + p->cq_off.overflow;
    cq->cqes = cq->ring_ptr + p->cq_off.cqes;

    return 0;
}

static int uring_init(struct uring *ring) {
    struct io_uring_params p;
    int ret;

    memset(&p, 0, sizeof(p));
    memset(ring, 0, sizeof(*ring));

    /*
     * Flags per CLAUDE.md:
     * - SUBMIT_ALL: All-or-nothing submission
     * - SINGLE_ISSUER: Skip submission locking (single-threaded)
     * - DEFER_TASKRUN: Batch completions, run on submit_and_wait
     * - COOP_TASKRUN: No async TWA interrupts
     * - CQSIZE: 4x SQ depth
     */
    p.flags = IORING_SETUP_SUBMIT_ALL |
              IORING_SETUP_SINGLE_ISSUER |
              IORING_SETUP_DEFER_TASKRUN |
              IORING_SETUP_COOP_TASKRUN |
              IORING_SETUP_CQSIZE;
    p.cq_entries = CQ_ENTRIES;

    ring->ring_fd = io_uring_setup(SQ_ENTRIES, &p);
    if (ring->ring_fd < 0)
        return -errno;

    ring->features = p.features;
    ring->flags = p.flags;
    ring->enter_ring_fd = ring->ring_fd;

    ret = uring_mmap(ring, &p);
    if (ret < 0) {
        close(ring->ring_fd);
        return ret;
    }

    return 0;
}

/* ============================================================================
 * SQE acquisition and submission - direct ring manipulation
 * ============================================================================ */

static inline struct io_uring_sqe *uring_get_sqe(struct uring *ring) {
    struct uring_sq *sq = &ring->sq;
    uint32_t head = smp_load_acquire(sq->khead);
    uint32_t next = sq->sqe_tail + 1;

    if (next - head > *sq->kring_entries)
        return NULL;

    struct io_uring_sqe *sqe = &sq->sqes[sq->sqe_tail & *sq->kring_mask];
    sq->sqe_tail = next;

    /* Clear the SQE - critical for correct operation */
    memset(sqe, 0, sizeof(*sqe));

    return sqe;
}

static inline void uring_sqe_set_data64(struct io_uring_sqe *sqe, uint64_t data) {
    sqe->user_data = data;
}

static inline int uring_submit(struct uring *ring) {
    struct uring_sq *sq = &ring->sq;
    uint32_t submitted = sq->sqe_tail - sq->sqe_head;

    if (!submitted)
        return 0;

    /* Fill SQ array with SQE indices */
    uint32_t mask = *sq->kring_mask;
    uint32_t ktail = *sq->ktail;

    for (uint32_t i = sq->sqe_head; i != sq->sqe_tail; i++) {
        sq->array[ktail & mask] = i & mask;
        ktail++;
    }

    smp_store_release(sq->ktail, ktail);
    sq->sqe_head = sq->sqe_tail;

    return submitted;
}

static inline int uring_submit_and_wait_timeout(struct uring *ring,
                                                  struct io_uring_cqe **cqe_ptr __attribute__((unused)),
                                                  unsigned wait_nr,
                                                  struct __kernel_timespec *ts) {
    int submitted = uring_submit(ring);
    unsigned flags = IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG;

    struct io_uring_getevents_arg arg = {
        .sigmask = 0,
        .sigmask_sz = _NSIG / 8,
        .ts = (uint64_t)ts
    };

    int ret = syscall(__NR_io_uring_enter, ring->ring_fd, submitted, wait_nr,
                      flags, &arg, sizeof(arg));
    if (ret < 0 && errno != ETIME)
        return -errno;

    return submitted >= 0 ? submitted : ret;
}

/* ============================================================================
 * CQE processing - direct ring access per CLAUDE.md
 * ============================================================================ */

static inline unsigned uring_cq_ready(struct uring *ring) {
    return smp_load_acquire(ring->cq.ktail) - *ring->cq.khead;
}

static inline struct io_uring_cqe *uring_peek_cqe(struct uring *ring) {
    struct uring_cq *cq = &ring->cq;
    uint32_t head = *cq->khead;
    uint32_t tail = smp_load_acquire(cq->ktail);

    if (head == tail)
        return NULL;

    return &cq->cqes[head & *cq->kring_mask];
}

static inline void uring_cq_advance(struct uring *ring, unsigned nr) {
    if (nr) {
        struct uring_cq *cq = &ring->cq;
        smp_store_release(cq->khead, *cq->khead + nr);
    }
}

/* ============================================================================
 * Provided buffer ring setup
 * ============================================================================ */

static int buf_ring_init(struct uring *ring, struct buf_ring *br) {
    size_t ring_size = (sizeof(struct io_uring_buf) + BUFFER_SIZE) * NUM_BUFFERS;

    /* Use huge pages if available, fall back to regular pages */
    void *ptr = mmap(NULL, ring_size, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
    if (ptr == MAP_FAILED) {
        ptr = mmap(NULL, ring_size, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
        if (ptr == MAP_FAILED)
            return -errno;
    }

    br->br = ptr;
    br->buf_base = (uint8_t *)ptr + (sizeof(struct io_uring_buf) * NUM_BUFFERS);
    br->buf_cnt = NUM_BUFFERS;
    br->buf_len = BUFFER_SIZE;
    br->tail = 0;
    br->bgid = BUFFER_GROUP_ID;

    /* Initialize buffer ring header */
    br->br->tail = 0;

    /* Add all buffers to the ring */
    for (uint32_t i = 0; i < NUM_BUFFERS; i++) {
        struct io_uring_buf *buf = &br->br->bufs[i];
        buf->addr = (uint64_t)(br->buf_base + (i * BUFFER_SIZE));
        buf->len = BUFFER_SIZE;
        buf->bid = i;
    }
    br->tail = NUM_BUFFERS;
    smp_store_release(&br->br->tail, br->tail);

    /* Register with kernel */
    struct io_uring_buf_reg reg = {
        .ring_addr = (uint64_t)br->br,
        .ring_entries = NUM_BUFFERS,
        .bgid = BUFFER_GROUP_ID,
    };

    int ret = io_uring_register(ring->ring_fd, IORING_REGISTER_PBUF_RING, &reg, 1);
    if (ret < 0)
        return ret;

    return 0;
}

static inline void buf_ring_add(struct buf_ring *br, uint16_t bid) {
    uint16_t tail = br->tail;
    struct io_uring_buf *buf = &br->br->bufs[tail & (br->buf_cnt - 1)];

    buf->addr = (uint64_t)(br->buf_base + (bid * br->buf_len));
    buf->len = br->buf_len;
    buf->bid = bid;

    br->tail = tail + 1;
    smp_store_release(&br->br->tail, br->tail);
}

static inline uint8_t *buf_ring_get_buf(struct buf_ring *br, uint16_t bid) {
    return br->buf_base + (bid * br->buf_len);
}

/* ============================================================================
 * SQE preparation helpers - no liburing, direct sqe setup
 * ============================================================================ */

static inline void prep_multishot_accept(struct io_uring_sqe *sqe, int fd) {
    sqe->opcode = IORING_OP_ACCEPT;
    sqe->fd = fd;
    sqe->addr = 0;  /* No sockaddr needed */
    sqe->addr2 = 0;
    sqe->accept_flags = 0;
    sqe->ioprio = IORING_ACCEPT_MULTISHOT;
}

static inline void prep_recv_multishot(struct io_uring_sqe *sqe, int fd, uint16_t bgid) {
    sqe->opcode = IORING_OP_RECV;
    sqe->fd = fd;
    sqe->addr = 0;
    sqe->len = 0; /* Required for multishot */
    sqe->msg_flags = 0;
    sqe->ioprio = IORING_RECV_MULTISHOT;
    sqe->flags = IOSQE_BUFFER_SELECT;
    sqe->buf_group = bgid;
}

static inline void prep_send(struct io_uring_sqe *sqe, int fd, const void *buf,
                              uint32_t len, int flags) {
    sqe->opcode = IORING_OP_SEND;
    sqe->fd = fd;
    sqe->addr = (uint64_t)buf;
    sqe->len = len;
    sqe->msg_flags = flags;
}

static inline void prep_close(struct io_uring_sqe *sqe, int fd) {
    sqe->opcode = IORING_OP_CLOSE;
    sqe->fd = fd;
}

/* ============================================================================
 * Listening socket setup
 * ============================================================================ */

static int create_listen_socket(int port, int cpu) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;

    /* SO_REUSEADDR - allow rapid restart */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("SO_REUSEADDR");
        close(fd);
        return -1;
    }

    /* SO_REUSEPORT - allow multiple listeners for load balancing */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("SO_REUSEPORT");
        close(fd);
        return -1;
    }

    /* SO_INCOMING_CPU - route packets to specific CPU (per CLAUDE.md) */
    if (setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, &cpu, sizeof(cpu)) < 0) {
        /* Non-fatal - might not be supported */
        fprintf(stderr, "Warning: SO_INCOMING_CPU not supported\n");
    }

    /* TCP_NODELAY - disable Nagle (per CLAUDE.md) */
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
        perror("TCP_NODELAY");
        close(fd);
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, LISTEN_BACKLOG) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

/* ============================================================================
 * CPU affinity setup (per CLAUDE.md)
 * ============================================================================ */

static int set_cpu_affinity(int cpu) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) < 0) {
        perror("sched_setaffinity");
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Event handlers
 * ============================================================================ */

struct server_ctx {
    struct uring ring;
    struct buf_ring br;
    int listen_fd;
    volatile bool running;
};

static void add_accept(struct server_ctx *ctx) {
    struct io_uring_sqe *sqe = uring_get_sqe(&ctx->ring);
    if (!sqe) {
        fprintf(stderr, "SQ full on accept\n");
        return;
    }

    prep_multishot_accept(sqe, ctx->listen_fd);
    uring_sqe_set_data64(sqe, encode_user_data(-1, OP_ACCEPT, 0));
}

static void add_recv(struct server_ctx *ctx, int client_fd) {
    struct io_uring_sqe *sqe = uring_get_sqe(&ctx->ring);
    if (!sqe) {
        fprintf(stderr, "SQ full on recv\n");
        return;
    }

    prep_recv_multishot(sqe, client_fd, BUFFER_GROUP_ID);
    uring_sqe_set_data64(sqe, encode_user_data(client_fd, OP_RECV, 0));
}

static void add_send(struct server_ctx *ctx, int client_fd, const void *data,
                     uint32_t len, uint16_t buf_idx) {
    struct io_uring_sqe *sqe = uring_get_sqe(&ctx->ring);
    if (!sqe) {
        fprintf(stderr, "SQ full on send\n");
        return;
    }

    prep_send(sqe, client_fd, data, len, 0);
    uring_sqe_set_data64(sqe, encode_user_data(client_fd, OP_SEND, buf_idx));
}

static void add_close(struct server_ctx *ctx, int client_fd) {
    struct io_uring_sqe *sqe = uring_get_sqe(&ctx->ring);
    if (!sqe) {
        fprintf(stderr, "SQ full on close\n");
        return;
    }

    prep_close(sqe, client_fd);
    uring_sqe_set_data64(sqe, encode_user_data(client_fd, OP_CLOSE, 0));
}

static void handle_accept(struct server_ctx *ctx, struct io_uring_cqe *cqe) {
    int client_fd = cqe->res;

    if (client_fd >= 0) {
        /* Set TCP_NODELAY on new connection */
        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        /* Start receiving on this connection */
        add_recv(ctx, client_fd);
    } else if (client_fd != -EAGAIN && client_fd != -EWOULDBLOCK) {
        fprintf(stderr, "Accept error: %d\n", client_fd);
    }

    /* Rearm accept if multishot ended */
    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        add_accept(ctx);
    }
}

static void handle_recv(struct server_ctx *ctx, struct io_uring_cqe *cqe, int client_fd) {
    int res = cqe->res;

    if (res <= 0) {
        /* EOF, error, or connection closed */
        if (res == 0 || res == -ECONNRESET || res == -EBADF || res == -EPIPE) {
            add_close(ctx, client_fd);
        } else if (res == -ENOBUFS) {
            /* No buffers available - multishot will retry automatically */
        } else {
            fprintf(stderr, "Recv error %d on fd %d\n", res, client_fd);
            add_close(ctx, client_fd);
        }
        return;
    }

    /* Got data - check for buffer flag */
    if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
        fprintf(stderr, "No buffer flag on recv\n");
        add_close(ctx, client_fd);
        return;
    }

    uint16_t buf_idx = cqe->flags >> IORING_CQE_BUFFER_SHIFT;

    /* Send HTTP 200 response */
    add_send(ctx, client_fd, HTTP_200_RESPONSE, HTTP_200_LEN, buf_idx);

    /* Rearm recv if multishot ended */
    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        add_recv(ctx, client_fd);
    }
}

static void handle_send(struct server_ctx *ctx, struct io_uring_cqe *cqe,
                        int client_fd, uint16_t buf_idx) {
    int res = cqe->res;

    /* Recycle buffer back to ring */
    buf_ring_add(&ctx->br, buf_idx);

    if (res < 0) {
        if (res == -EPIPE || res == -ECONNRESET || res == -EBADF) {
            add_close(ctx, client_fd);
        } else {
            fprintf(stderr, "Send error %d on fd %d\n", res, client_fd);
        }
    }
    /* Connection stays open for keep-alive */
}

/* ============================================================================
 * Main event loop - per CLAUDE.md architecture
 *
 * "Single-syscall submit/wait pattern"
 * "CQ drain via direct ring access"
 * ============================================================================ */

static void event_loop(struct server_ctx *ctx) {
    struct __kernel_timespec ts = { .tv_sec = 1, .tv_nsec = 0 };

    /* Start multishot accept */
    add_accept(ctx);

    while (ctx->running) {
        struct io_uring_cqe *cqe;

        /* Single syscall submit + wait per CLAUDE.md */
        int ret = uring_submit_and_wait_timeout(&ctx->ring, &cqe, 1, &ts);
        if (ret < 0 && ret != -ETIME) {
            if (ret == -EINTR)
                continue;
            fprintf(stderr, "submit_and_wait error: %d\n", ret);
            break;
        }

        /*
         * Direct CQ drain per CLAUDE.md:
         * "Acquire-release semantics match kernel expectations"
         */
        uint32_t head = *ctx->ring.cq.khead;
        uint32_t tail = smp_load_acquire(ctx->ring.cq.ktail);
        uint32_t processed = 0;

        while (head != tail) {
            struct io_uring_cqe *cqe = &ctx->ring.cq.cqes[head & *ctx->ring.cq.kring_mask];

            uint64_t user_data = cqe->user_data;
            int32_t fd = decode_fd(user_data);
            uint8_t op = decode_op(user_data);
            uint16_t buf_idx = decode_buf_idx(user_data);

            switch (op) {
            case OP_ACCEPT:
                handle_accept(ctx, cqe);
                break;
            case OP_RECV:
                handle_recv(ctx, cqe, fd);
                break;
            case OP_SEND:
                handle_send(ctx, cqe, fd, buf_idx);
                break;
            case OP_CLOSE:
                /* Close complete - nothing to do */
                break;
            }

            head++;
            processed++;
        }

        /* Release CQ entries */
        smp_store_release(ctx->ring.cq.khead, head);
    }
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char *argv[]) {
    int port = 8080;
    int cpu = 0;

    if (argc > 1)
        port = atoi(argv[1]);
    if (argc > 2)
        cpu = atoi(argv[2]);

    printf("Raw io_uring HTTP server (no liburing)\n");
    printf("  Port: %d\n", port);
    printf("  CPU: %d\n", cpu);
    printf("  SQ entries: %d\n", SQ_ENTRIES);
    printf("  CQ entries: %d\n", CQ_ENTRIES);
    printf("  Buffers: %d x %d bytes\n", NUM_BUFFERS, BUFFER_SIZE);

    /* Pin to CPU per CLAUDE.md */
    if (set_cpu_affinity(cpu) < 0) {
        fprintf(stderr, "Warning: Failed to set CPU affinity\n");
    }

    struct server_ctx ctx = { .running = true };

    /* Initialize io_uring */
    int ret = uring_init(&ctx.ring);
    if (ret < 0) {
        fprintf(stderr, "io_uring init failed: %s\n", strerror(-ret));
        return 1;
    }
    printf("  io_uring features: 0x%x\n", ctx.ring.features);

    /* Initialize buffer ring */
    ret = buf_ring_init(&ctx.ring, &ctx.br);
    if (ret < 0) {
        fprintf(stderr, "Buffer ring init failed: %s\n", strerror(-ret));
        return 1;
    }
    printf("  Buffer ring initialized\n");

    /* Create listening socket */
    ctx.listen_fd = create_listen_socket(port, cpu);
    if (ctx.listen_fd < 0) {
        return 1;
    }
    printf("  Listening on port %d\n", port);
    printf("\nServer ready. Ctrl+C to stop.\n\n");

    /* Run event loop */
    event_loop(&ctx);

    return 0;
}
