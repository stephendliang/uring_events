/*
  Raw io_uring HTTP server - No liburing, maximum performance
  - Shared-nothing per-core isolation
  - No liburing (direct syscalls + ring manipulation)
  - IORING_SETUP_SUBMIT_ALL, SINGLE_ISSUER, DEFER_TASKRUN, COOP_TASKRUN
  - Multishot accept + multishot recv with provided buffers
  - Zero allocation in hot path
  - Zero context switches in steady state
 */

#define _GNU_SOURCE

#include <sched.h>

#include <signal.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "core.h"
#include "event.h"
#include "util.h"

// SIMD infrastructure for SQE template copy
#if defined(__AVX512F__)
#include "sqe_avx512.h"
#elif defined(__AVX2__)
#include "sqe_avx2.h"
#else
#include "sqe_scalar.h"
#endif

// Configuration - All tunable at compile time
enum {
    SQ_ENTRIES      = 2048,
    CQ_ENTRIES      = SQ_ENTRIES * 4,
    NUM_BUFFERS     = 4096,
    BUFFER_SIZE     = 2048,
    BUFFER_SHIFT    = 11,
    BUFFER_GROUP_ID = 0,
    LISTEN_BACKLOG  = 4096,
    MAX_CONNECTIONS = 65536,
};

/* Compile-time validation */
_Static_assert((NUM_BUFFERS & (NUM_BUFFERS - 1)) == 0, "NUM_BUFFERS must be power of 2");
_Static_assert(NUM_BUFFERS <= 32768, "NUM_BUFFERS max is 32768");
_Static_assert(BUFFER_SIZE >= 64, "BUFFER_SIZE too small");
_Static_assert((1 << BUFFER_SHIFT) == BUFFER_SIZE, "BUFFER_SHIFT must match BUFFER_SIZE");
_Static_assert(SQ_ENTRIES >= 256, "SQ_ENTRIES too small");

#include "uring.h"

// HTTP response - precomputed at compile time
static const char HTTP_200_RESPONSE[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 2\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "OK";

#define HTTP_200_LEN (sizeof(HTTP_200_RESPONSE) - 1)

/* Context encoding - pack into 64-bit user_data
   Layout: [fd:32][op:8][buf_idx:16][unused:8] */
enum op_type {
    OP_ACCEPT     = 0,
    OP_RECV       = 1,
    OP_SEND       = 2,
    OP_CLOSE      = 3,
    OP_SETSOCKOPT = 4,
#ifdef ENABLE_ZC
    OP_SEND_ZC    = 5,
#endif
};

// Pre-shifted operation codes for faster encoding
#define OP_ACCEPT_SHIFTED     ((u64)OP_ACCEPT << 32)
#define OP_RECV_SHIFTED       ((u64)OP_RECV << 32)
#define OP_SEND_SHIFTED       ((u64)OP_SEND << 32)
#define OP_CLOSE_SHIFTED      ((u64)OP_CLOSE << 32)
#define OP_SETSOCKOPT_SHIFTED ((u64)OP_SETSOCKOPT << 32)
#ifdef ENABLE_ZC
#define OP_SEND_ZC_SHIFTED    ((u64)OP_SEND_ZC << 32)
#endif

// SQE templates — 64-byte aligned for SIMD copy, fd/user_data patched per-op
#define CACHE_ALIGN __attribute__((aligned(64)))

CACHE_ALIGN
static const struct io_uring_sqe SQE_TEMPLATE_ACCEPT = {
    .opcode     = IORING_OP_ACCEPT,
    .flags      = IOSQE_FIXED_FILE,
    .ioprio     = IORING_ACCEPT_MULTISHOT,
    .user_data  = OP_ACCEPT_SHIFTED | 0xFFFFFFFF,
    .file_index = IORING_FILE_INDEX_ALLOC,
};

CACHE_ALIGN
static const struct io_uring_sqe SQE_TEMPLATE_RECV = {
    .opcode    = IORING_OP_RECV,
    .flags     = IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE,
    .ioprio    = IORING_RECV_MULTISHOT,
    .len       = 0, /* MUST be 0 for multishot */
    .buf_group = BUFFER_GROUP_ID,
};

CACHE_ALIGN
static struct io_uring_sqe SQE_TEMPLATE_SEND = { /* non-const: addr set at init */
    .opcode = IORING_OP_SEND,
    .flags  = IOSQE_FIXED_FILE,
    .len    = HTTP_200_LEN,
};

CACHE_ALIGN
static const struct io_uring_sqe SQE_TEMPLATE_CLOSE = {
    .opcode = IORING_OP_CLOSE,
    .flags  = IOSQE_FIXED_FILE,
};

#ifdef ENABLE_ZC
// ZC buffer group ID - distinct from recv buffer group
#ifndef ZC_BUFFER_GROUP_ID
#define ZC_BUFFER_GROUP_ID      1
#endif
#ifndef ZC_NUM_BUFFERS
#define ZC_NUM_BUFFERS          1024
#endif
#ifndef ZC_BUFFER_SIZE
#define ZC_BUFFER_SIZE          4096
#endif
#ifndef ZC_BUFFER_SHIFT
#define ZC_BUFFER_SHIFT         12  /* log2(ZC_BUFFER_SIZE) */
#endif

_Static_assert((ZC_NUM_BUFFERS & (ZC_NUM_BUFFERS - 1)) == 0,
               "ZC_NUM_BUFFERS must be power of 2");
_Static_assert((1 << ZC_BUFFER_SHIFT) == ZC_BUFFER_SIZE,
               "ZC_BUFFER_SHIFT must match ZC_BUFFER_SIZE");

CACHE_ALIGN
static const struct io_uring_sqe SQE_TEMPLATE_SEND_ZC = {
    .opcode    = IORING_OP_SEND_ZC,
    .flags     = IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT,
    .ioprio    = IORING_RECVSEND_BUNDLE,
    .buf_group = ZC_BUFFER_GROUP_ID,
};
#endif // ENABLE_ZC

// Connection state - bit-packed for cache efficiency
struct conn_state {
    u8 closing : 1;
    u8 recv_active : 1;
    u8 reserved : 6;
};

CACHE_ALIGN static struct conn_state g_conns[MAX_CONNECTIONS];

// Static value for async setsockopt - must persist across async operation
static int g_tcp_nodelay_val = 1;

static inline struct conn_state *get_conn(int fd) {
    // Bounds check - returns NULL for invalid fd
    unsigned ufd = (unsigned)fd;
    return (ufd < MAX_CONNECTIONS) ? &g_conns[ufd] : NULL;
}

#define decode_fd(ud) ((i32)((ud) & 0xFFFFFFFF))
#define decode_op(ud) ((u8)((ud) >> 32))
#define decode_buf_idx(ud) ((u16)((ud) >> 40))

// SQE prep wrappers - macro dispatch to PREP_SQE (defined by sqe_*.h)
#define prep_multishot_accept_direct(sqe, fd) \
    PREP_SQE(sqe, SQE_TEMPLATE_ACCEPT, fd, OP_ACCEPT_SHIFTED | 0xFFFFFFFF)

#define prep_recv_multishot_direct(sqe, fd) \
    PREP_SQE(sqe, SQE_TEMPLATE_RECV, fd, OP_RECV_SHIFTED | (u32)(fd))

#define prep_send_direct(sqe, fd, buf, len, buf_idx) do { \
    (void)(buf); (void)(len); \
    PREP_SQE(sqe, SQE_TEMPLATE_SEND, fd, OP_SEND_SHIFTED | (u32)(fd) | ((u64)(buf_idx) << 40)); \
} while (0)

#define prep_close_direct(sqe, fd) \
    PREP_SQE(sqe, SQE_TEMPLATE_CLOSE, fd, OP_CLOSE_SHIFTED | (u32)(fd))

#ifdef ENABLE_ZC
#define prep_send_zc_direct(sqe, fd, buf_idx) \
    PREP_SQE(sqe, SQE_TEMPLATE_SEND_ZC, fd, OP_SEND_ZC_SHIFTED | (u32)(fd) | ((u64)(buf_idx) << 40))
#endif

/* SETSOCKOPT: SIMD zero + scalar patches. SQEs are 64-byte aligned. */
static inline void prep_setsockopt_direct(struct io_uring_sqe *sqe, int idx,
                                           int level, int optname,
                                           void *optval, int optlen) {
    mem_zero_cacheline(sqe);
    sqe->opcode = IORING_OP_URING_CMD;
    sqe->flags = IOSQE_CQE_SKIP_SUCCESS | IOSQE_FIXED_FILE;
    sqe->fd = idx;
    sqe->user_data = OP_SETSOCKOPT_SHIFTED | (u32)idx;
    // cmd area at offset 48: level(4)|optname(4)|optlen(4)|pad(4)|optval(8)
    u8 *cmd = (u8 *)sqe + 48;
    *(u32 *)(cmd + 0) = (u32)level;
    *(u32 *)(cmd + 4) = (u32)optname;
    *(u32 *)(cmd + 8) = (u32)optlen;
    *(u64 *)(cmd + 16) = (u64)(uintptr_t)optval;
}

// Listening socket setup (startup path - not performance critical)
static int create_listen_socket(u16 port, int cpu) {
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
        .sin_port = htons(port),
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

// CPU affinity (startup path)
static int set_cpu_affinity(int cpu) {
    if (cpu < 0 || cpu >= CPU_SETSIZE)
        return -1;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    return sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

// Server context
struct server_ctx {
    struct uring ring;
    struct buf_ring_mgr br_mgr;
    struct buf_ring_group *recv_grp;    // Pointer into br_mgr.groups[0]
#ifdef ENABLE_ZC
    struct buf_ring_group *zc_grp;      // Pointer into br_mgr.groups[1]
    bool zc_enabled;
#endif
    // Legacy buf_ring for hot path caching (populated from recv_grp)
    struct buf_ring br;
    int listen_fd;
    sig_atomic_t running;  // Proper type for signal handlers
};

static struct server_ctx *g_ctx = NULL;

static void signal_handler(int sig) {
    (void)sig;
    if (g_ctx)
        g_ctx->running = 0;
}

// Event handlers
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

static inline bool queue_send(struct server_ctx *ctx, int fd, u16 buf_idx) {
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
        return true;  // Already queued

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

#ifdef ENABLE_ZC
static inline bool queue_send_zc(struct server_ctx *ctx, int fd,
                                  const void *data, u32 len) {
    struct conn_state *c = get_conn(fd);
    if (unlikely(!c) || c->closing)
        return false;

    u16 buf_idx = buf_ring_zc_alloc(ctx->zc_grp);
    if (unlikely(buf_idx == UINT16_MAX)) {
        LOG_WARN("zc: no buffers fd=%d", fd);
        return false;
    }

    void *buf = BUF_RING_ADDR(&ctx->br_mgr, ctx->zc_grp, buf_idx);
    u32 copy_len = (len > ZC_BUFFER_SIZE) ? ZC_BUFFER_SIZE : len;
    memcpy(buf, data, copy_len);

    buf_ring_zc_push(&ctx->br_mgr, ctx->zc_grp, buf_idx, copy_len);
    buf_ring_mgr_sync(&ctx->br_mgr, ctx->zc_grp);

    struct io_uring_sqe *sqe = uring_get_sqe(&ctx->ring);
    if (unlikely(!sqe)) {
        LOG_ERROR("zc: SQ full fd=%d", fd);
        return false;
    }

    prep_send_zc_direct(sqe, fd, buf_idx);
    return true;
}

static inline void handle_send_zc(struct server_ctx *ctx,
                                   struct io_uring_cqe *cqe, int fd) {
    u16 buf_idx = decode_buf_idx(cqe->user_data);

    if (cqe->flags & IORING_CQE_F_NOTIF) {
        // Notification: buffer safe to reuse
        buf_ring_zc_recycle(ctx->zc_grp, buf_idx);
        return;
    }

    // Completion: send done, buffer still in-flight to NIC
    int res = cqe->res;
    if (unlikely(res < 0)) {
        if (res != -EPIPE && res != -ECONNRESET && res != -EBADF && res != -ECANCELED)
            LOG_ERROR("zc send error %d fd=%d", res, fd);
        queue_close(ctx, fd);
    }
    // Do NOT recycle - wait for NOTIF
}
#endif // ENABLE_ZC

static inline void handle_setsockopt(struct server_ctx *ctx,
                                      struct io_uring_cqe *cqe, int fd) {
    (void)ctx; (void)fd;
    if (unlikely(cqe->res < 0)) {
        LOG_WARN("setsockopt failed fd=%d res=%d", fd, cqe->res);
    }
    // TCP_NODELAY failure is non-fatal, connection proceeds
}

static inline void handle_accept(struct server_ctx *ctx, struct io_uring_cqe *cqe) {
    int idx = cqe->res;  // Fixed file INDEX, not fd

    if (likely(idx >= 0)) {
        struct conn_state *c = get_conn(idx);  // idx used as connection ID
        if (likely(c)) {
            c->closing = 0;
            c->recv_active = 0;

            // Async TCP_NODELAY via io_uring - kernel resolves fixed file internally
            queue_setsockopt_nodelay(ctx, idx);

            if (unlikely(!queue_recv(ctx, idx))) {
                queue_close(ctx, idx); // Async close
            }
        } else {
            queue_close(ctx, idx); // Async close
        }
    } else if (idx != -EAGAIN && idx != -EWOULDBLOCK && idx != -ECANCELED) {
        LOG_ERROR("accept error: %d", idx);
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

    u16 buf_idx = (u16)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);

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

static inline void handle_close(int fd) {
    struct conn_state *c = get_conn(fd);
    if (c) {
        c->closing = 0;
        c->recv_active = 0;
    }
}

// Main event loop
static void event_loop(struct server_ctx *ctx) {
    struct __kernel_timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };  // 1ms

    if (unlikely(!queue_accept(ctx))) {
        LOG_FATAL("Failed to start accept");
        return;
    }

    // Cache frequently accessed values
    struct uring_cq *cq = &ctx->ring.cq;
    const u32 cq_mask = cq->ring_mask;
    struct io_uring_cqe *cqes = cq->cqes;

    // Cache buf_ring invariants - these never change after init
    struct io_uring_buf_ring *const br_ring = ctx->br.br;
    u8 *const br_base = ctx->br.buf_base;
    const u16 br_mask = ctx->br.mask;

    // Cache CQ head - we're the only writer, no need to re-read from shared memory
    u32 head = *cq->khead;

    while (likely(ctx->running)) {
        int ret = uring_submit_and_wait(&ctx->ring, 1, &ts);
        if (unlikely(ret < 0 && ret != -ETIME && ret != -EINTR)) {
            LOG_FATAL("submit_and_wait: %d", ret);
            break;
        }

        u32 tail = smp_load_acquire(cq->ktail);

        // Cache buffer ring tail locally for this batch
        u16 br_tail = ctx->br.tail;
        const u16 br_tail_start = br_tail;

        while (head != tail) {
            struct io_uring_cqe *cqe = &cqes[head & cq_mask];

            // Prefetch next CQE
            prefetch_r(&cqes[(head + 1) & cq_mask]);

            u64 ud = cqe->user_data;
            int32_t fd = decode_fd(ud);
            u8 op = decode_op(ud);

            switch (op) {
            case OP_ACCEPT:
                handle_accept(ctx, cqe);
                break;
            case OP_RECV:
                ctx->br.tail = br_tail;   // Sync cached → ctx before call
                handle_recv(ctx, cqe, fd);
                br_tail = ctx->br.tail;   // Sync ctx → cached after call
                break;
            case OP_SEND: {
                u16 buf_idx = decode_buf_idx(ud);
                // Recycle buffer
                struct io_uring_buf *buf = &br_ring->bufs[br_tail & br_mask];
                buf->addr = (u64)(br_base + ((u32)buf_idx << BUFFER_SHIFT));
                buf->len = BUFFER_SIZE;
                buf->bid = buf_idx;
                br_tail++;
                int res = cqe->res;
                if (unlikely(res < 0)) {
                    if (res != -EPIPE && res != -ECONNRESET && res != -EBADF && res != -ECANCELED)
                        LOG_ERROR("send error %d fd=%d", res, fd);
                    queue_close(ctx, fd);
                } else if (unlikely((u32)res < HTTP_200_LEN)) {
                    LOG_WARN("partial send fd=%d %d/%zu", fd, res, HTTP_200_LEN);
                    queue_close(ctx, fd);
                }
                break;
            }
            case OP_CLOSE:
                handle_close(fd);
                break;
            case OP_SETSOCKOPT:
                handle_setsockopt(ctx, cqe, fd);
                break;
#ifdef ENABLE_ZC
            case OP_SEND_ZC:
                handle_send_zc(ctx, cqe, fd);
                break;
#endif
            default:
                LOG_BUG("unknown op %u", op);
                break;
            }

            head++;
        }

        // Write back cached tail and sync if buffers were recycled
        ctx->br.tail = br_tail;
        ctx->recv_grp->tail = br_tail;  // Keep recv_grp in sync
        if (br_tail != br_tail_start)
            buf_ring_sync(&ctx->br);
        smp_store_release(cq->khead, head);
    }

    LOG_INFO("Event loop exiting");
}

int server_run(u16 port, int cpu) {
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

    mem_zero_aligned(g_conns, sizeof(g_conns));

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Initialize SEND template with runtime address
    SQE_TEMPLATE_SEND.addr = (u64)HTTP_200_RESPONSE;

    int ret = uring_init(&ctx.ring, SQ_ENTRIES, CQ_ENTRIES);
    if (ret < 0) {
        LOG_FATAL("io_uring init: %d", ret);
        return 1;
    }
    LOG_INFO("io_uring features: 0x%x", ctx.ring.features);

    // Initialize unified buffer ring manager
    struct buf_ring_config configs[] = {
        { .num_buffers = NUM_BUFFERS, .buffer_size = BUFFER_SIZE,
          .buffer_shift = BUFFER_SHIFT, .bgid = BUFFER_GROUP_ID,
#ifdef ENABLE_ZC
          .is_zc = 0
#endif
        },
#ifdef ENABLE_ZC
        { .num_buffers = ZC_NUM_BUFFERS, .buffer_size = ZC_BUFFER_SIZE,
          .buffer_shift = ZC_BUFFER_SHIFT, .bgid = ZC_BUFFER_GROUP_ID,
          .is_zc = 1 },
#endif
    };
    ret = buf_ring_mgr_init(&ctx.ring, &ctx.br_mgr, configs,
                             sizeof(configs)/sizeof(configs[0]));
    if (ret < 0) {
        LOG_FATAL("buffer ring manager init: %d", ret);
        return 1;
    }
    ctx.recv_grp = &ctx.br_mgr.groups[0];
#ifdef ENABLE_ZC
    ctx.zc_grp = &ctx.br_mgr.groups[1];
    // Probe for ZC support
    ret = buf_ring_zc_probe(&ctx.ring);
    ctx.zc_enabled = (ret == 0);
    if (ctx.zc_enabled) {
        LOG_INFO("Zerocopy send enabled");
    } else {
        LOG_INFO("Zerocopy send not available (ret=%d)", ret);
    }
#endif

    // Setup legacy buf_ring struct for hot path (points into br_mgr)
    ctx.br.br = BUF_RING_PTR(&ctx.br_mgr, ctx.recv_grp);
    ctx.br.buf_base = BUF_RING_DATA(&ctx.br_mgr, ctx.recv_grp);
    ctx.br.tail = ctx.recv_grp->tail;
    ctx.br.mask = ctx.recv_grp->mask;
    ctx.br.buffer_size = ctx.recv_grp->buffer_size;
    ctx.br.buffer_shift = ctx.recv_grp->buffer_shift;

    int listen_fd = create_listen_socket(port, cpu);
    if (listen_fd < 0) {
        return 1;
    }

    // Register fixed file table for direct accept
    ret = uring_register_fixed_files(&ctx.ring, MAX_CONNECTIONS);
    if (ret < 0) {
        LOG_FATAL("fixed file registration: %d", ret);
        close(listen_fd);
        return 1;
    }
    LOG_INFO("Fixed file table registered: %d slots", MAX_CONNECTIONS);

    /* Install listen_fd as fixed file index 0 */
    int install_fds[1] = { listen_fd };
    struct io_uring_files_update update = {
        .offset = 0,
        .fds = (u64)(uintptr_t)install_fds,
    };
    ret = io_uring_register(ctx.ring.ring_fd, IORING_REGISTER_FILES_UPDATE, &update, 1);
    if (ret < 0) {
        LOG_FATAL("listen socket install: %d", ret);
        close(listen_fd);
        return 1;
    }

    // Close the original fd - fixed file table has the reference now
    close(listen_fd);
    ctx.listen_fd = 0;  // Now this is the fixed file index

    LOG_INFO("Listening on port %d (fixed file index 0)", port);

    event_loop(&ctx);

    // Cleanup buffer ring manager (unregisters from kernel, single munmap)
    buf_ring_mgr_destroy(&ctx.ring, &ctx.br_mgr);

    // listen_fd is now a fixed file index - gets cleaned up with ring.
    // Only close the ring fd
    close(ctx.ring.ring_fd);

    LOG_INFO("Server stopped");
    return 0;
}
