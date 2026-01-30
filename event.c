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
 * SIMD infrastructure for SQE template copy
 * ============================================================================ */

#if defined(__AVX512F__)
#include <immintrin.h>
#define USE_AVX512 1
#elif defined(__AVX2__)
#include <immintrin.h>
#define USE_AVX2 1
#endif

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
 * Context encoding - pack into 64-bit user_data
 * Layout: [fd:32][op:8][buf_idx:16][unused:8]
 * ============================================================================ */

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

/* Pre-shifted operation codes for faster encoding */
#define OP_ACCEPT_SHIFTED     ((uint64_t)OP_ACCEPT << 32)
#define OP_RECV_SHIFTED       ((uint64_t)OP_RECV << 32)
#define OP_SEND_SHIFTED       ((uint64_t)OP_SEND << 32)
#define OP_CLOSE_SHIFTED      ((uint64_t)OP_CLOSE << 32)
#define OP_SETSOCKOPT_SHIFTED ((uint64_t)OP_SETSOCKOPT << 32)
#ifdef ENABLE_ZC
#define OP_SEND_ZC_SHIFTED    ((uint64_t)OP_SEND_ZC << 32)
#endif

/* ============================================================================
 * SQE templates - 64-byte aligned for SIMD copy
 * Only fd and user_data vary per operation; everything else is constant.
 * ============================================================================ */

__attribute__((aligned(64)))
static const struct io_uring_sqe SQE_TEMPLATE_ACCEPT = {
    .opcode = IORING_OP_ACCEPT,
    .flags = IOSQE_FIXED_FILE,              /* Use fixed file for listen_fd */
    .ioprio = IORING_ACCEPT_MULTISHOT,
    .fd = 0,  /* Fixed file index of listen socket */
    .off = 0,
    .addr = 0,
    .len = 0,
    .accept_flags = 0,
    .user_data = OP_ACCEPT_SHIFTED | 0xFFFFFFFF,  /* constant: idx = -1 */
    .buf_group = 0,
    .personality = 0,
    .file_index = IORING_FILE_INDEX_ALLOC,  /* Kernel allocates fixed file slot */
    .addr3 = 0,
    .__pad2 = {0},
};

__attribute__((aligned(64)))
static const struct io_uring_sqe SQE_TEMPLATE_RECV = {
    .opcode = IORING_OP_RECV,
    .flags = IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE,  /* Fixed file for client socket */
    .ioprio = IORING_RECV_MULTISHOT,
    .fd = 0,  /* Fixed file index, not fd */
    .off = 0,
    .addr = 0,
    .len = 0,  /* MUST be 0 for multishot */
    .msg_flags = 0,
    .user_data = 0,  /* patched */
    .buf_group = BUFFER_GROUP_ID,
    .personality = 0,
    .splice_fd_in = 0,
    .addr3 = 0,
    .__pad2 = {0},
};

__attribute__((aligned(64)))
static struct io_uring_sqe SQE_TEMPLATE_SEND = {  /* non-const: addr set at init */
    .opcode = IORING_OP_SEND,
    .flags = IOSQE_FIXED_FILE,  /* Fixed file for client socket */
    .ioprio = 0,
    .fd = 0,  /* Fixed file index, not fd */
    .off = 0,
    .addr = 0,  /* set to HTTP_200_RESPONSE at init */
    .len = HTTP_200_LEN,
    .msg_flags = 0,
    .user_data = 0,  /* patched */
    .buf_group = 0,
    .personality = 0,
    .splice_fd_in = 0,
    .addr3 = 0,
    .__pad2 = {0},
};

__attribute__((aligned(64)))
static const struct io_uring_sqe SQE_TEMPLATE_CLOSE = {
    .opcode = IORING_OP_CLOSE,
    .flags = IOSQE_FIXED_FILE,  /* Fixed file for client socket */
    .ioprio = 0,
    .fd = 0,  /* Fixed file index, not fd */
    .off = 0,
    .addr = 0,
    .len = 0,
    .rw_flags = 0,
    .user_data = 0,  /* patched */
    .buf_group = 0,
    .personality = 0,
    .splice_fd_in = 0,
    .addr3 = 0,
    .__pad2 = {0},
};

#ifdef ENABLE_ZC
/* ZC buffer group ID - distinct from recv buffer group */
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

__attribute__((aligned(64)))
static const struct io_uring_sqe SQE_TEMPLATE_SEND_ZC = {
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
#endif /* ENABLE_ZC */

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

/* Context encoding helpers (unused - inlined at call sites)
static inline uint64_t encode_accept(void) {
    return OP_ACCEPT_SHIFTED | 0xFFFFFFFF;
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
*/

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
 * SQE preparation - Template copy + patch using SIMD
 *
 * AVX-512: Load template into ZMM, patch fd/user_data in-register, single store.
 *          Zero store-forwarding stalls.
 * AVX2:    Two 256-bit loads/stores, then narrow patches.
 * Scalar:  Struct copy, then narrow patches.
 * ============================================================================ */

#ifdef USE_AVX512

static inline void prep_multishot_accept_direct(struct io_uring_sqe *sqe, int fd) {
    __m512i zmm = _mm512_load_si512((const __m512i *)&SQE_TEMPLATE_ACCEPT);
    /* Patch fd at dword index 1 (byte offset 4) */
    zmm = _mm512_mask_set1_epi32(zmm, 1U << 1, fd);
    /* user_data is constant in template */
    _mm512_store_si512((__m512i *)sqe, zmm);
}

static inline void prep_recv_multishot_direct(struct io_uring_sqe *sqe, int fd) {
    __m512i zmm = _mm512_load_si512((const __m512i *)&SQE_TEMPLATE_RECV);
    /* Patch fd at dword index 1 (byte offset 4) */
    zmm = _mm512_mask_set1_epi32(zmm, 1U << 1, fd);
    /* Patch user_data at qword index 4 (byte offset 32) */
    uint64_t ud = OP_RECV_SHIFTED | (uint32_t)fd;
    zmm = _mm512_mask_set1_epi64(zmm, 1U << 4, (long long)ud);
    _mm512_store_si512((__m512i *)sqe, zmm);
}

static inline void prep_send_direct(struct io_uring_sqe *sqe, int fd,
                                     const void *buf, uint32_t len,
                                     uint16_t buf_idx) {
    (void)buf; (void)len;  /* Template has pre-set addr and len */
    __m512i zmm = _mm512_load_si512((const __m512i *)&SQE_TEMPLATE_SEND);
    /* Patch fd at dword index 1 (byte offset 4) */
    zmm = _mm512_mask_set1_epi32(zmm, 1U << 1, fd);
    /* Patch user_data at qword index 4 (byte offset 32) */
    uint64_t ud = OP_SEND_SHIFTED | (uint32_t)fd | ((uint64_t)buf_idx << 40);
    zmm = _mm512_mask_set1_epi64(zmm, 1U << 4, (long long)ud);
    _mm512_store_si512((__m512i *)sqe, zmm);
}

static inline void prep_close_direct(struct io_uring_sqe *sqe, int fd) {
    __m512i zmm = _mm512_load_si512((const __m512i *)&SQE_TEMPLATE_CLOSE);
    /* Patch fd at dword index 1 (byte offset 4) */
    zmm = _mm512_mask_set1_epi32(zmm, 1U << 1, fd);
    /* Patch user_data at qword index 4 (byte offset 32) */
    uint64_t ud = OP_CLOSE_SHIFTED | (uint32_t)fd;
    zmm = _mm512_mask_set1_epi64(zmm, 1U << 4, (long long)ud);
    _mm512_store_si512((__m512i *)sqe, zmm);
}

#ifdef ENABLE_ZC
static inline void prep_send_zc_direct(struct io_uring_sqe *sqe, int fd,
                                        uint16_t buf_idx) {
    __m512i zmm = _mm512_load_si512((const __m512i *)&SQE_TEMPLATE_SEND_ZC);
    zmm = _mm512_mask_set1_epi32(zmm, 1U << 1, fd);
    uint64_t ud = OP_SEND_ZC_SHIFTED | (uint32_t)fd | ((uint64_t)buf_idx << 40);
    zmm = _mm512_mask_set1_epi64(zmm, 1U << 4, (long long)ud);
    _mm512_store_si512((__m512i *)sqe, zmm);
}
#endif

#else  /* AVX2 or scalar fallback */

#ifdef USE_AVX2

static inline void prep_multishot_accept_direct(struct io_uring_sqe *sqe, int fd) {
    __m256i lo = _mm256_load_si256((const __m256i *)&SQE_TEMPLATE_ACCEPT);
    __m256i hi = _mm256_load_si256((const __m256i *)&SQE_TEMPLATE_ACCEPT + 1);
    lo = _mm256_blend_epi32(lo, _mm256_set1_epi32(fd), 1 << 1);
    _mm256_store_si256((__m256i *)sqe, lo);
    _mm256_store_si256((__m256i *)sqe + 1, hi);
}

static inline void prep_recv_multishot_direct(struct io_uring_sqe *sqe, int fd) {
    __m256i lo = _mm256_load_si256((const __m256i *)&SQE_TEMPLATE_RECV);
    __m256i hi = _mm256_load_si256((const __m256i *)&SQE_TEMPLATE_RECV + 1);
    lo = _mm256_blend_epi32(lo, _mm256_set1_epi32(fd), 1 << 1);
    uint64_t ud = OP_RECV_SHIFTED | (uint32_t)fd;
    hi = _mm256_blend_epi32(hi, _mm256_set1_epi64x((long long)ud), 0x03);
    _mm256_store_si256((__m256i *)sqe, lo);
    _mm256_store_si256((__m256i *)sqe + 1, hi);
}

static inline void prep_send_direct(struct io_uring_sqe *sqe, int fd,
                                     const void *buf, uint32_t len,
                                     uint16_t buf_idx) {
    (void)buf; (void)len;
    __m256i lo = _mm256_load_si256((const __m256i *)&SQE_TEMPLATE_SEND);
    __m256i hi = _mm256_load_si256((const __m256i *)&SQE_TEMPLATE_SEND + 1);
    lo = _mm256_blend_epi32(lo, _mm256_set1_epi32(fd), 1 << 1);
    uint64_t ud = OP_SEND_SHIFTED | (uint32_t)fd | ((uint64_t)buf_idx << 40);
    hi = _mm256_blend_epi32(hi, _mm256_set1_epi64x((long long)ud), 0x03);
    _mm256_store_si256((__m256i *)sqe, lo);
    _mm256_store_si256((__m256i *)sqe + 1, hi);
}

static inline void prep_close_direct(struct io_uring_sqe *sqe, int fd) {
    __m256i lo = _mm256_load_si256((const __m256i *)&SQE_TEMPLATE_CLOSE);
    __m256i hi = _mm256_load_si256((const __m256i *)&SQE_TEMPLATE_CLOSE + 1);
    lo = _mm256_blend_epi32(lo, _mm256_set1_epi32(fd), 1 << 1);
    uint64_t ud = OP_CLOSE_SHIFTED | (uint32_t)fd;
    hi = _mm256_blend_epi32(hi, _mm256_set1_epi64x((long long)ud), 0x03);
    _mm256_store_si256((__m256i *)sqe, lo);
    _mm256_store_si256((__m256i *)sqe + 1, hi);
}

#ifdef ENABLE_ZC
static inline void prep_send_zc_direct(struct io_uring_sqe *sqe, int fd,
                                        uint16_t buf_idx) {
    __m256i lo = _mm256_load_si256((const __m256i *)&SQE_TEMPLATE_SEND_ZC);
    __m256i hi = _mm256_load_si256((const __m256i *)&SQE_TEMPLATE_SEND_ZC + 1);
    lo = _mm256_blend_epi32(lo, _mm256_set1_epi32(fd), 1 << 1);
    uint64_t ud = OP_SEND_ZC_SHIFTED | (uint32_t)fd | ((uint64_t)buf_idx << 40);
    hi = _mm256_blend_epi32(hi, _mm256_set1_epi64x((long long)ud), 0x03);
    _mm256_store_si256((__m256i *)sqe, lo);
    _mm256_store_si256((__m256i *)sqe + 1, hi);
}
#endif

#else  /* Scalar fallback */

static inline void sqe_copy_64(struct io_uring_sqe *dst,
                                const struct io_uring_sqe *src) {
    *dst = *src;
}

static inline void prep_multishot_accept_direct(struct io_uring_sqe *sqe, int fd) {
    sqe_copy_64(sqe, &SQE_TEMPLATE_ACCEPT);
    sqe->fd = fd;
}

static inline void prep_recv_multishot_direct(struct io_uring_sqe *sqe, int fd) {
    sqe_copy_64(sqe, &SQE_TEMPLATE_RECV);
    sqe->fd = fd;
    sqe->user_data = OP_RECV_SHIFTED | (uint32_t)fd;
}

static inline void prep_send_direct(struct io_uring_sqe *sqe, int fd,
                                     const void *buf, uint32_t len,
                                     uint16_t buf_idx) {
    (void)buf; (void)len;
    sqe_copy_64(sqe, &SQE_TEMPLATE_SEND);
    sqe->fd = fd;
    sqe->user_data = OP_SEND_SHIFTED | (uint32_t)fd | ((uint64_t)buf_idx << 40);
}

static inline void prep_close_direct(struct io_uring_sqe *sqe, int fd) {
    sqe_copy_64(sqe, &SQE_TEMPLATE_CLOSE);
    sqe->fd = fd;
    sqe->user_data = OP_CLOSE_SHIFTED | (uint32_t)fd;
}

#ifdef ENABLE_ZC
static inline void prep_send_zc_direct(struct io_uring_sqe *sqe, int fd,
                                        uint16_t buf_idx) {
    sqe_copy_64(sqe, &SQE_TEMPLATE_SEND_ZC);
    sqe->fd = fd;
    sqe->user_data = OP_SEND_ZC_SHIFTED | (uint32_t)fd | ((uint64_t)buf_idx << 40);
}
#endif

#endif  /* USE_AVX2 / scalar */

#endif  /* USE_AVX512 */

/* SETSOCKOPT: Keep scalar - complex cmd area at offset 48, rare operation */
static inline void prep_setsockopt_direct(struct io_uring_sqe *sqe, int idx,
                                           int level, int optname,
                                           void *optval, int optlen) {
    sqe->opcode = IORING_OP_URING_CMD;
    sqe->flags = IOSQE_CQE_SKIP_SUCCESS | IOSQE_FIXED_FILE;  /* Fixed file for client socket */
    sqe->ioprio = 0;
    sqe->fd = idx;  /* Fixed file index */
    sqe->off = 0;  /* cmd_op = SOCKET_URING_OP_SETSOCKOPT (0) */
    sqe->addr = 0;
    sqe->len = 0;
    sqe->rw_flags = 0;
    sqe->user_data = OP_SETSOCKOPT_SHIFTED | (uint32_t)idx;
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
    struct buf_ring_mgr br_mgr;
    struct buf_ring_group *recv_grp;    /* Pointer into br_mgr.groups[0] */
#ifdef ENABLE_ZC
    struct buf_ring_group *zc_grp;      /* Pointer into br_mgr.groups[1] */
    bool zc_enabled;
#endif
    /* Legacy buf_ring for hot path caching (populated from recv_grp) */
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

#ifdef ENABLE_ZC
static inline bool queue_send_zc(struct server_ctx *ctx, int fd,
                                  const void *data, uint32_t len) {
    struct conn_state *c = get_conn(fd);
    if (unlikely(!c) || c->closing)
        return false;

    uint16_t buf_idx = buf_ring_zc_alloc(ctx->zc_grp);
    if (unlikely(buf_idx == UINT16_MAX)) {
        LOG_WARN("zc: no buffers fd=%d", fd);
        return false;
    }

    void *buf = buf_ring_mgr_addr(&ctx->br_mgr, ctx->zc_grp, buf_idx);
    uint32_t copy_len = (len > ZC_BUFFER_SIZE) ? ZC_BUFFER_SIZE : len;
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
    uint16_t buf_idx = decode_buf_idx(cqe->user_data);

    if (cqe->flags & IORING_CQE_F_NOTIF) {
        /* Notification: buffer safe to reuse */
        buf_ring_zc_recycle(ctx->zc_grp, buf_idx);
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
#endif /* ENABLE_ZC */

static inline void handle_setsockopt(struct server_ctx *ctx,
                                      struct io_uring_cqe *cqe, int fd) {
    (void)ctx; (void)fd;
    if (unlikely(cqe->res < 0)) {
        LOG_WARN("setsockopt failed fd=%d res=%d", fd, cqe->res);
    }
    /* TCP_NODELAY failure is non-fatal, connection proceeds */
}

static inline void handle_accept(struct server_ctx *ctx, struct io_uring_cqe *cqe) {
    int idx = cqe->res;  /* Fixed file INDEX, not fd */

    if (likely(idx >= 0)) {
        struct conn_state *c = get_conn(idx);  /* idx used as connection ID */
        if (likely(c)) {
            c->closing = 0;
            c->recv_active = 0;

            /* Async TCP_NODELAY via io_uring - kernel resolves fixed file internally */
            queue_setsockopt_nodelay(ctx, idx);

            if (unlikely(!queue_recv(ctx, idx))) {
                queue_close(ctx, idx);  /* Async close */
            }
        } else {
            queue_close(ctx, idx);  /* Async close */
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

static void event_loop(struct server_ctx *ctx) {
    struct __kernel_timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };  // 1ms

    if (unlikely(!queue_accept(ctx))) {
        LOG_FATAL("Failed to start accept");
        return;
    }

    /* Cache frequently accessed values */
    struct uring_cq *cq = &ctx->ring.cq;
    const uint32_t cq_mask = cq->ring_mask;
    struct io_uring_cqe *cqes = cq->cqes;

    /* Cache buf_ring invariants - these never change after init */
    struct io_uring_buf_ring *const br_ring = ctx->br.br;
    uint8_t *const br_base = ctx->br.buf_base;
    const uint16_t br_mask = ctx->br.mask;

    /* Cache CQ head - we're the only writer, no need to re-read from shared memory */
    uint32_t head = *cq->khead;

    while (likely(ctx->running)) {
        int ret = uring_submit_and_wait(&ctx->ring, 1, &ts);
        if (unlikely(ret < 0 && ret != -ETIME && ret != -EINTR)) {
            LOG_FATAL("submit_and_wait: %d", ret);
            break;
        }

        uint32_t tail = smp_load_acquire(cq->ktail);

        /* Cache buffer ring tail locally for this batch */
        uint16_t br_tail = ctx->br.tail;
        const uint16_t br_tail_start = br_tail;

        while (head != tail) {
            struct io_uring_cqe *cqe = &cqes[head & cq_mask];

            /* Prefetch next CQE */
            prefetch_r(&cqes[(head + 1) & cq_mask]);

            uint64_t ud = cqe->user_data;
            int32_t fd = decode_fd(ud);
            uint8_t op = decode_op(ud);

            /* Switch dispatch - enables inlining and uses direct branches */
            switch (op) {
            case OP_ACCEPT:
                handle_accept(ctx, cqe);
                break;
            case OP_RECV:
                ctx->br.tail = br_tail;   /* Sync cached → ctx before call */
                handle_recv(ctx, cqe, fd);
                br_tail = ctx->br.tail;   /* Sync ctx → cached after call */
                break;
            case OP_SEND: {
                uint16_t buf_idx = decode_buf_idx(ud);
                /* Inline buffer recycling with cached values */
                struct io_uring_buf *buf = &br_ring->bufs[br_tail & br_mask];
                buf->addr = (uint64_t)(br_base + ((uint32_t)buf_idx << BUFFER_SHIFT));
                buf->len = BUFFER_SIZE;
                buf->bid = buf_idx;
                br_tail++;
                /* Send completion error checking */
                int res = cqe->res;
                if (unlikely(res < 0)) {
                    if (res != -EPIPE && res != -ECONNRESET && res != -EBADF && res != -ECANCELED)
                        LOG_ERROR("send error %d fd=%d", res, fd);
                    queue_close(ctx, fd);
                } else if (unlikely((uint32_t)res < HTTP_200_LEN)) {
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

        /* Write back cached tail and sync if buffers were recycled */
        ctx->br.tail = br_tail;
        ctx->recv_grp->tail = br_tail;  /* Keep recv_grp in sync */
        if (br_tail != br_tail_start)
            buf_ring_sync(&ctx->br);
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

    /* Initialize SEND template with runtime address */
    SQE_TEMPLATE_SEND.addr = (uint64_t)HTTP_200_RESPONSE;

    int ret = uring_init(&ctx.ring);
    if (ret < 0) {
        LOG_FATAL("io_uring init: %d", ret);
        return 1;
    }
    LOG_INFO("io_uring features: 0x%x", ctx.ring.features);

    /* Initialize unified buffer ring manager */
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
    /* Probe for ZC support */
    ret = buf_ring_zc_probe(&ctx.ring);
    ctx.zc_enabled = (ret == 0);
    if (ctx.zc_enabled) {
        LOG_INFO("Zerocopy send enabled");
    } else {
        LOG_INFO("Zerocopy send not available (ret=%d)", ret);
    }
#endif

    /* Setup legacy buf_ring struct for hot path (points into br_mgr) */
    ctx.br.br = BUF_RING_PTR(&ctx.br_mgr, ctx.recv_grp);
    ctx.br.buf_base = BUF_RING_DATA(&ctx.br_mgr, ctx.recv_grp);
    ctx.br.tail = ctx.recv_grp->tail;
    ctx.br.mask = ctx.recv_grp->mask;

    int listen_fd = create_listen_socket(port, cpu);
    if (listen_fd < 0) {
        return 1;
    }

    /* Register fixed file table for direct accept */
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
        .fds = (uint64_t)(uintptr_t)install_fds,
    };
    ret = io_uring_register(ctx.ring.ring_fd, IORING_REGISTER_FILES_UPDATE, &update, 1);
    if (ret < 0) {
        LOG_FATAL("listen socket install: %d", ret);
        close(listen_fd);
        return 1;
    }

    /* Close the original fd - fixed file table has the reference now */
    close(listen_fd);
    ctx.listen_fd = 0;  /* Now this is the fixed file index */

    LOG_INFO("Listening on port %d (fixed file index 0)", port);

    event_loop(&ctx);

    /* Cleanup buffer ring manager (unregisters from kernel, single munmap) */
    buf_ring_mgr_destroy(&ctx.ring, &ctx.br_mgr);

    /* listen_fd is now a fixed file index - gets cleaned up with ring.
     * Only close the ring fd. */
    close(ctx.ring.ring_fd);

    LOG_INFO("Server stopped");
    return 0;
}
