#pragma once
// bench_sqe.h — Scalar SQE prep for disk I/O benchmark.
// Uses mem_zero_cacheline + field writes, matching prep_setsockopt_direct.

#include "uring.h"
#include "bench_syscalls.h"

#include <linux/io_uring.h>

// user_data encoding: [slot:16 | reserved:48]
// Simple — just the buffer slot index for identifying in-flight ops.
#define BENCH_ENCODE_UD(slot) ((u64)(slot))
#define BENCH_DECODE_SLOT(ud) ((u32)((ud) & 0xFFFF))

static inline void bench_prep_read(struct io_uring_sqe *sqe,
                                    int fd, void *buf, u32 len,
                                    u64 offset, u32 slot,
                                    __kernel_rwf_t rw_flags) {
    mem_zero_cacheline(sqe);
    sqe->opcode    = IORING_OP_READ;
    sqe->fd        = fd;
    sqe->off       = offset;
    sqe->addr      = (u64)(uintptr_t)buf;
    sqe->len       = len;
    sqe->user_data = BENCH_ENCODE_UD(slot);
    sqe->rw_flags  = rw_flags;
}

static inline void bench_prep_write(struct io_uring_sqe *sqe,
                                     int fd, const void *buf, u32 len,
                                     u64 offset, u32 slot,
                                     __kernel_rwf_t rw_flags) {
    mem_zero_cacheline(sqe);
    sqe->opcode    = IORING_OP_WRITE;
    sqe->fd        = fd;
    sqe->off       = offset;
    sqe->addr      = (u64)(uintptr_t)buf;
    sqe->len       = len;
    sqe->user_data = BENCH_ENCODE_UD(slot);
    sqe->rw_flags  = rw_flags;
}

static inline void bench_prep_fsync(struct io_uring_sqe *sqe, int fd) {
    mem_zero_cacheline(sqe);
    sqe->opcode    = IORING_OP_FSYNC;
    sqe->fd        = fd;
    sqe->user_data = BENCH_ENCODE_UD(0xFFFF);  // Sentinel
}

static inline void bench_prep_fdatasync(struct io_uring_sqe *sqe,
                                         int fd, u64 user_data) {
    mem_zero_cacheline(sqe);
    sqe->opcode      = IORING_OP_FSYNC;
    sqe->fd          = fd;
    sqe->user_data   = user_data;
    sqe->fsync_flags = IORING_FSYNC_DATASYNC;
}
