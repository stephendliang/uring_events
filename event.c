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
 *
 * Build:
 *   Production: gcc -DNDEBUG -O3 ...
 *   Debug:      gcc -DDEBUG -O0 -g ...
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sched.h>
#include <limits.h>

#include <signal.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* ============================================================================
 * Debug/Logging macros - compiled out in production (NDEBUG)
 * ============================================================================ */

#ifdef DEBUG
  #define LOG_INFO(fmt, ...)  fprintf(stderr, "[INFO] " fmt "\n", ##__VA_ARGS__)
  #define LOG_WARN(fmt, ...)  fprintf(stderr, "[WARN] " fmt "\n", ##__VA_ARGS__)
  #define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
  #define LOG_BUG(fmt, ...)   fprintf(stderr, "[BUG] " fmt "\n", ##__VA_ARGS__)
  #define DEBUG_ONLY(x)       x
#else
  #define LOG_INFO(fmt, ...)  ((void)0)
  #define LOG_WARN(fmt, ...)  ((void)0)
  #define LOG_ERROR(fmt, ...) ((void)0)
  #define LOG_BUG(fmt, ...)   ((void)0)
  #define DEBUG_ONLY(x)       ((void)0)
#endif

/* Fatal errors that should crash even in production */
#define LOG_FATAL(fmt, ...) do { \
    fprintf(stderr, "[FATAL] " fmt "\n", ##__VA_ARGS__); \
} while(0)

/* Branch prediction hints */
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* Prefetch for read */
#define prefetch_r(addr) __builtin_prefetch((addr), 0, 3)

/* ============================================================================
 * Configuration - All tunable at compile time
 * ============================================================================ */

#define SQ_ENTRIES          2048
#define CQ_ENTRIES          (SQ_ENTRIES * 4)    /* 4x SQ per CLAUDE.md */
#define NUM_BUFFERS         4096
#define BUFFER_SIZE         2048
#define BUFFER_SHIFT        11                   /* log2(BUFFER_SIZE) */
#define BUFFER_GROUP_ID     0
#define LISTEN_BACKLOG      4096
#define MAX_CONNECTIONS     65536

/* Compile-time validation */
_Static_assert((NUM_BUFFERS & (NUM_BUFFERS - 1)) == 0, "NUM_BUFFERS must be power of 2");
_Static_assert(NUM_BUFFERS <= 32768, "NUM_BUFFERS max is 32768");
_Static_assert(BUFFER_SIZE >= 64, "BUFFER_SIZE too small");
_Static_assert((1 << BUFFER_SHIFT) == BUFFER_SIZE, "BUFFER_SHIFT must match BUFFER_SIZE");
_Static_assert(SQ_ENTRIES >= 256, "SQ_ENTRIES too small");

#include "uring.h"

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
 * Connection state - bit-packed for cache efficiency
 * ============================================================================ */

struct conn_state {
    uint8_t closing : 1;
    uint8_t recv_active : 1;
    uint8_t reserved : 6;
};

static struct conn_state g_conns[MAX_CONNECTIONS];

/* Static value for async setsockopt - must persist across async operation */
static int g_tcp_nodelay_val = 1;

static inline struct conn_state *get_conn(int fd) {
    /* Branchless bounds check - returns NULL for invalid fd */
    unsigned ufd = (unsigned)fd;
    return (ufd < MAX_CONNECTIONS) ? &g_conns[ufd] : NULL;
}

/* ============================================================================
 * Context encoding - pack into 64-bit user_data
 * Layout: [fd:32][op:8][buf_idx:16][unused:8]
 * ============================================================================ */

enum op_type {
    OP_ACCEPT     = 0,
    OP_RECV       = 1,
    OP_SEND       = 2,
    OP_CLOSE      = 3,
    OP_SETSOCKOPT = 4,
};

/* Pre-shifted operation codes for faster encoding */
#define OP_ACCEPT_SHIFTED     ((uint64_t)OP_ACCEPT << 32)
#define OP_RECV_SHIFTED       ((uint64_t)OP_RECV << 32)
#define OP_SEND_SHIFTED       ((uint64_t)OP_SEND << 32)
#define OP_CLOSE_SHIFTED      ((uint64_t)OP_CLOSE << 32)
#define OP_SETSOCKOPT_SHIFTED ((uint64_t)OP_SETSOCKOPT << 32)

static inline uint64_t encode_accept(void) {
    return OP_ACCEPT_SHIFTED | 0xFFFFFFFF; /* fd = -1 */
}

static inline uint64_t encode_recv(int fd) {
    return OP_RECV_SHIFTED | (uint32_t)fd;
}

static inline uint64_t encode_send(int fd, uint16_t buf_idx) {
    return OP_SEND_SHIFTED | (uint32_t)fd | ((uint64_t)buf_idx << 40);
}

static inline uint64_t encode_close(int fd) {
    return OP_CLOSE_SHIFTED | (uint32_t)fd;
}

static inline int32_t decode_fd(uint64_t ud) {
    return (int32_t)(ud & 0xFFFFFFFF);
}

static inline uint8_t decode_op(uint64_t ud) {
    return (uint8_t)(ud >> 32);
}

static inline uint16_t decode_buf_idx(uint64_t ud) {
    return (uint16_t)(ud >> 40);
}

/* ============================================================================
 * SQE preparation - OPTIMIZED: only set required fields, no memset
 * ============================================================================ */

static inline void prep_multishot_accept_direct(struct io_uring_sqe *sqe, int fd) {
    sqe->opcode = IORING_OP_ACCEPT;
    sqe->flags = 0;
    sqe->ioprio = IORING_ACCEPT_MULTISHOT;
    sqe->fd = fd;
    sqe->off = 0;
    sqe->addr = 0;
    sqe->len = 0;
    sqe->accept_flags = 0;
    sqe->user_data = encode_accept();
    sqe->buf_group = 0;
    sqe->personality = 0;
    sqe->splice_fd_in = 0;
    sqe->addr3 = 0;
    sqe->__pad2[0] = 0;
}

static inline void prep_recv_multishot_direct(struct io_uring_sqe *sqe, int fd) {
    sqe->opcode = IORING_OP_RECV;
    sqe->flags = IOSQE_BUFFER_SELECT;
    sqe->ioprio = IORING_RECV_MULTISHOT;
    sqe->fd = fd;
    sqe->off = 0;
    sqe->addr = 0;
    sqe->len = 0;  /* MUST be 0 for multishot */
    sqe->msg_flags = 0;
    sqe->user_data = encode_recv(fd);
    sqe->buf_group = BUFFER_GROUP_ID;
    sqe->personality = 0;
    sqe->splice_fd_in = 0;
    sqe->addr3 = 0;
    sqe->__pad2[0] = 0;
}

static inline void prep_send_direct(struct io_uring_sqe *sqe, int fd,
                                     const void *buf, uint32_t len,
                                     uint16_t buf_idx) {
    sqe->opcode = IORING_OP_SEND;
    sqe->flags = 0;
    sqe->ioprio = 0;
    sqe->fd = fd;
    sqe->off = 0;
    sqe->addr = (uint64_t)buf;
    sqe->len = len;
    sqe->msg_flags = 0;
    sqe->user_data = encode_send(fd, buf_idx);
    sqe->buf_group = 0;
    sqe->personality = 0;
    sqe->splice_fd_in = 0;
    sqe->addr3 = 0;
    sqe->__pad2[0] = 0;
}

static inline void prep_close_direct(struct io_uring_sqe *sqe, int fd) {
    sqe->opcode = IORING_OP_CLOSE;
    sqe->flags = 0;
    sqe->ioprio = 0;
    sqe->fd = fd;
    sqe->off = 0;
    sqe->addr = 0;
    sqe->len = 0;
    sqe->rw_flags = 0;
    sqe->user_data = encode_close(fd);
    sqe->buf_group = 0;
    sqe->personality = 0;
    sqe->splice_fd_in = 0;
    sqe->addr3 = 0;
    sqe->__pad2[0] = 0;
}

static inline void prep_setsockopt_direct(struct io_uring_sqe *sqe, int fd,
                                           int level, int optname,
                                           void *optval, int optlen) {
    sqe->opcode = IORING_OP_URING_CMD;
    sqe->flags = 0;
    sqe->ioprio = 0;
    sqe->fd = fd;
    sqe->off = 0;  /* cmd_op = SOCKET_URING_OP_SETSOCKOPT (0) */
    sqe->addr = 0;
    sqe->len = 0;
    sqe->rw_flags = 0;
    sqe->user_data = OP_SETSOCKOPT_SHIFTED | (uint32_t)fd;
    sqe->buf_group = 0;
    sqe->personality = 0;
    sqe->splice_fd_in = 0;
    sqe->addr3 = 0;
    sqe->__pad2[0] = 0;

    /* Socket command parameters in cmd array (offset 48 in SQE)
     * Layout: level(4) | optname(4) | optlen(4) | pad(4) | optval(8) */
    uint8_t *cmd = (uint8_t *)sqe + 48;
    *(uint32_t *)(cmd + 0) = (uint32_t)level;
    *(uint32_t *)(cmd + 4) = (uint32_t)optname;
    *(uint32_t *)(cmd + 8) = (uint32_t)optlen;
    *(uint32_t *)(cmd + 12) = 0;  /* padding */
    *(uint64_t *)(cmd + 16) = (uint64_t)(uintptr_t)optval;
}

/* ============================================================================
 * Listening socket setup (startup path - not performance critical)
 * ============================================================================ */

static int create_listen_socket(int port, int cpu) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        LOG_FATAL("socket: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, &cpu, sizeof(cpu));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_FATAL("bind: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, LISTEN_BACKLOG) < 0) {
        LOG_FATAL("listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/* ============================================================================
 * CPU affinity (startup path)
 * ============================================================================ */

static int set_cpu_affinity(int cpu) {
    if (cpu < 0 || cpu >= CPU_SETSIZE)
        return -1;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    return sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

/* ============================================================================
 * Server context
 * ============================================================================ */

struct server_ctx {
    struct uring ring;
    struct buf_ring br;
    int listen_fd;
    sig_atomic_t running;  /* Proper type for signal handlers */
};

static struct server_ctx *g_ctx = NULL;

static void signal_handler(int sig) {
    (void)sig;
    if (g_ctx)
        g_ctx->running = 0;
}

/* ============================================================================
 * Event handlers - HOT PATH, maximally optimized
 * ============================================================================ */

static inline bool queue_accept(struct server_ctx *ctx) {
    struct io_uring_sqe *sqe = uring_get_sqe(&ctx->ring);
    if (unlikely(!sqe)) {
        LOG_ERROR("SQ full on accept");
        return false;
    }
    prep_multishot_accept_direct(sqe, ctx->listen_fd);
    return true;
}

static inline bool queue_recv(struct server_ctx *ctx, int fd) {
    struct conn_state *c = get_conn(fd);
    if (unlikely(!c) || c->closing)
        return false;

    struct io_uring_sqe *sqe = uring_get_sqe(&ctx->ring);
    if (unlikely(!sqe)) {
        LOG_ERROR("SQ full on recv fd=%d", fd);
        return false;
    }
    prep_recv_multishot_direct(sqe, fd);
    c->recv_active = 1;
    return true;
}

static inline bool queue_send(struct server_ctx *ctx, int fd, uint16_t buf_idx) {
    struct conn_state *c = get_conn(fd);
    if (unlikely(!c) || c->closing) {
        buf_ring_recycle(&ctx->br, buf_idx);
        return false;
    }

    struct io_uring_sqe *sqe = uring_get_sqe(&ctx->ring);
    if (unlikely(!sqe)) {
        LOG_ERROR("SQ full on send fd=%d", fd);
        buf_ring_recycle(&ctx->br, buf_idx);
        return false;
    }
    prep_send_direct(sqe, fd, HTTP_200_RESPONSE, HTTP_200_LEN, buf_idx);
    return true;
}

static inline bool queue_close(struct server_ctx *ctx, int fd) {
    struct conn_state *c = get_conn(fd);
    if (unlikely(!c))
        return false;

    if (c->closing)
        return true;  /* Already queued */

    struct io_uring_sqe *sqe = uring_get_sqe(&ctx->ring);
    if (unlikely(!sqe)) {
        LOG_ERROR("SQ full on close fd=%d", fd);
        c->closing = 1;  /* Mark to prevent further ops */
        return false;
    }
    prep_close_direct(sqe, fd);
    c->closing = 1;
    return true;
}

static inline bool queue_setsockopt_nodelay(struct server_ctx *ctx, int fd) {
    struct io_uring_sqe *sqe = uring_get_sqe(&ctx->ring);
    if (unlikely(!sqe)) {
        LOG_WARN("SQ full on setsockopt fd=%d", fd);
        return false;
    }
    prep_setsockopt_direct(sqe, fd, IPPROTO_TCP, TCP_NODELAY,
                           &g_tcp_nodelay_val, sizeof(g_tcp_nodelay_val));
    return true;
}

static inline void handle_setsockopt(struct server_ctx *ctx,
                                      struct io_uring_cqe *cqe, int fd) {
    (void)ctx; (void)fd;
    if (unlikely(cqe->res < 0)) {
        LOG_WARN("setsockopt failed fd=%d res=%d", fd, cqe->res);
    }
    /* TCP_NODELAY failure is non-fatal, connection proceeds */
}

static inline void handle_accept(struct server_ctx *ctx, struct io_uring_cqe *cqe) {
    int fd = cqe->res;

    if (likely(fd >= 0)) {
        struct conn_state *c = get_conn(fd);
        if (likely(c)) {
            c->closing = 0;
            c->recv_active = 0;

            /* Async TCP_NODELAY via io_uring - no syscall in hot path! */
            queue_setsockopt_nodelay(ctx, fd);

            if (unlikely(!queue_recv(ctx, fd))) {
                queue_close(ctx, fd);  /* Async close */
            }
        } else {
            queue_close(ctx, fd);  /* Async close */
        }
    } else if (fd != -EAGAIN && fd != -EWOULDBLOCK && fd != -ECANCELED) {
        LOG_ERROR("accept error: %d", fd);
    }

    if (unlikely(!(cqe->flags & IORING_CQE_F_MORE))) {
        if (!queue_accept(ctx)) {
            LOG_FATAL("Cannot rearm accept");
            ctx->running = 0;
        }
    }
}

static inline void handle_recv(struct server_ctx *ctx, struct io_uring_cqe *cqe, int fd) {
    struct conn_state *c = get_conn(fd);
    int res = cqe->res;
    bool more = (cqe->flags & IORING_CQE_F_MORE) != 0;

    if (!more && c)
        c->recv_active = 0;

    if (unlikely(res <= 0)) {
        if (res == 0 || res == -ECONNRESET || res == -EBADF ||
            res == -EPIPE || res == -ECANCELED) {
            queue_close(ctx, fd);
        } else if (res == -ENOBUFS) {
            LOG_WARN("ENOBUFS fd=%d", fd);
            if (!more && c && !c->closing)
                queue_recv(ctx, fd);
        } else {
            LOG_ERROR("recv error %d fd=%d", res, fd);
            queue_close(ctx, fd);
        }
        return;
    }

    if (unlikely(!(cqe->flags & IORING_CQE_F_BUFFER))) {
        LOG_BUG("no buffer flag fd=%d", fd);
        queue_close(ctx, fd);
        return;
    }

    uint16_t buf_idx = (uint16_t)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);

    DEBUG_ONLY(if (buf_idx >= NUM_BUFFERS) {
        LOG_BUG("invalid buf_idx %u fd=%d", buf_idx, fd);
        queue_close(ctx, fd);
        return;
    });

    if (unlikely(!queue_send(ctx, fd, buf_idx))) {
        queue_close(ctx, fd);
        return;
    }

    if (unlikely(!more && c && !c->closing)) {
        queue_recv(ctx, fd);
    }
}

static inline void handle_send(struct server_ctx *ctx, struct io_uring_cqe *cqe,
                                int fd, uint16_t buf_idx) {
    /* Always recycle buffer first */
    buf_ring_recycle(&ctx->br, buf_idx);

    int res = cqe->res;
    if (unlikely(res < 0)) {
        if (res != -EPIPE && res != -ECONNRESET && res != -EBADF && res != -ECANCELED) {
            LOG_ERROR("send error %d fd=%d", res, fd);
        }
        queue_close(ctx, fd);
    } else if (unlikely((uint32_t)res < HTTP_200_LEN)) {
        LOG_WARN("partial send fd=%d %d/%zu", fd, res, HTTP_200_LEN);
        queue_close(ctx, fd);
    }
    /* Success: connection stays open for keep-alive */
}

static inline void handle_close(int fd) {
    struct conn_state *c = get_conn(fd);
    if (c) {
        c->closing = 0;
        c->recv_active = 0;
    }
}

/* ============================================================================
 * Main event loop - ULTRA HOT PATH
 * ============================================================================ */

/* Handler jump table for branchless dispatch */
typedef void (*cqe_handler_t)(struct server_ctx *, struct io_uring_cqe *, int, uint16_t);

static void handle_accept_wrapper(struct server_ctx *ctx, struct io_uring_cqe *cqe,
                                   int fd, uint16_t buf_idx) {
    (void)fd; (void)buf_idx;
    handle_accept(ctx, cqe);
}

static void handle_recv_wrapper(struct server_ctx *ctx, struct io_uring_cqe *cqe,
                                 int fd, uint16_t buf_idx) {
    (void)buf_idx;
    handle_recv(ctx, cqe, fd);
}

static void handle_send_wrapper(struct server_ctx *ctx, struct io_uring_cqe *cqe,
                                 int fd, uint16_t buf_idx) {
    handle_send(ctx, cqe, fd, buf_idx);
}

static void handle_close_wrapper(struct server_ctx *ctx, struct io_uring_cqe *cqe,
                                  int fd, uint16_t buf_idx) {
    (void)ctx; (void)cqe; (void)buf_idx;
    handle_close(fd);
}

static void handle_setsockopt_wrapper(struct server_ctx *ctx, struct io_uring_cqe *cqe,
                                       int fd, uint16_t buf_idx) {
    (void)buf_idx;
    handle_setsockopt(ctx, cqe, fd);
}

static const cqe_handler_t g_handlers[5] = {
    [OP_ACCEPT]     = handle_accept_wrapper,
    [OP_RECV]       = handle_recv_wrapper,
    [OP_SEND]       = handle_send_wrapper,
    [OP_CLOSE]      = handle_close_wrapper,
    [OP_SETSOCKOPT] = handle_setsockopt_wrapper,
};

static void event_loop(struct server_ctx *ctx) {
    struct __kernel_timespec ts = { .tv_sec = 1, .tv_nsec = 0 };

    if (unlikely(!queue_accept(ctx))) {
        LOG_FATAL("Failed to start accept");
        return;
    }

    /* Cache frequently accessed values */
    struct uring_cq *cq = &ctx->ring.cq;
    const uint32_t cq_mask = cq->ring_mask;
    struct io_uring_cqe *cqes = cq->cqes;

    while (likely(ctx->running)) {
        int ret = uring_submit_and_wait(&ctx->ring, 1, &ts);
        if (unlikely(ret < 0 && ret != -ETIME && ret != -EINTR)) {
            LOG_FATAL("submit_and_wait: %d", ret);
            break;
        }

        uint32_t head = *cq->khead;
        uint32_t tail = smp_load_acquire(cq->ktail);

        while (head != tail) {
            struct io_uring_cqe *cqe = &cqes[head & cq_mask];

            /* Prefetch next CQE */
            prefetch_r(&cqes[(head + 1) & cq_mask]);

            uint64_t ud = cqe->user_data;
            int32_t fd = decode_fd(ud);
            uint8_t op = decode_op(ud);
            uint16_t buf_idx = decode_buf_idx(ud);

            /* Jump table dispatch - no branch misprediction */
            if (likely(op < 5)) {
                g_handlers[op](ctx, cqe, fd, buf_idx);
            } else {
                LOG_BUG("unknown op %u", op);
            }

            head++;
        }

        smp_store_release(cq->khead, head);
    }

    LOG_INFO("Event loop exiting");
}

/* ============================================================================
 * Input validation (startup only)
 * ============================================================================ */

static int parse_int(const char *str, int min, int max, const char *name) {
    char *end;
    errno = 0;
    long val = strtol(str, &end, 10);

    if (errno || end == str || *end != '\0' || val < min || val > max) {
        LOG_FATAL("Invalid %s: '%s' (must be %d-%d)", name, str, min, max);
        return -1;
    }
    return (int)val;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char *argv[]) {
    int port = 8080;
    int cpu = 0;

    if (argc > 1) {
        port = parse_int(argv[1], 1, 65535, "port");
        if (port < 0) return 1;
    }
    if (argc > 2) {
        cpu = parse_int(argv[2], 0, CPU_SETSIZE - 1, "cpu");
        if (cpu < 0) return 1;
    }

#ifdef DEBUG
    fprintf(stderr, "=== DEBUG BUILD - NOT FOR PRODUCTION ===\n");
#endif

    LOG_INFO("io_uring server starting - port=%d cpu=%d sq=%d cq=%d bufs=%dx%d",
             port, cpu, SQ_ENTRIES, CQ_ENTRIES, NUM_BUFFERS, BUFFER_SIZE);

    if (set_cpu_affinity(cpu) < 0) {
        LOG_WARN("Failed to set CPU affinity");
    }

    struct server_ctx ctx = { .running = 1 };
    g_ctx = &ctx;

    /* Clear connection state */
    memset(g_conns, 0, sizeof(g_conns));

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int ret = uring_init(&ctx.ring);
    if (ret < 0) {
        LOG_FATAL("io_uring init: %d", ret);
        return 1;
    }
    LOG_INFO("io_uring features: 0x%x", ctx.ring.features);

    ret = buf_ring_init(&ctx.ring, &ctx.br);
    if (ret < 0) {
        LOG_FATAL("buffer ring init: %d", ret);
        return 1;
    }

    ctx.listen_fd = create_listen_socket(port, cpu);
    if (ctx.listen_fd < 0) {
        return 1;
    }

    LOG_INFO("Listening on port %d", port);

    event_loop(&ctx);

    close(ctx.listen_fd);
    close(ctx.ring.ring_fd);

    LOG_INFO("Server stopped");
    return 0;
}
