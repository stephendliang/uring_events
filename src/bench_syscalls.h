#pragma once
// bench_syscalls.h — Disk I/O syscall wrappers layered on nolibc.h.
// Kept separate to avoid bloating nolibc.h with file-I/O calls the
// HTTP server binary never uses.

#include "nolibc.h"

#include <linux/fcntl.h>   // AT_FDCWD, O_DIRECT, O_CREAT, O_RDWR, O_TRUNC
#include <linux/fs.h>      // RWF_DONTCACHE
#include <linux/time.h>    // CLOCK_MONOTONIC
#include <linux/fadvise.h> // POSIX_FADV_DONTNEED

// RWF_DONTCACHE: merged in 6.16, flag value 0x80
#ifndef RWF_DONTCACHE
#define RWF_DONTCACHE ((__kernel_rwf_t)0x80)
#endif

static inline int sys_openat(int dirfd, const char *pathname,
                              int flags, int mode) {
    return (int)_syscall4(__NR_openat, dirfd, pathname, flags, mode);
}

static inline int sys_fallocate(int fd, int mode, long offset, long len) {
    return (int)_syscall4(__NR_fallocate, fd, mode, offset, len);
}

static inline int sys_ftruncate(int fd, long length) {
    return (int)_syscall2(__NR_ftruncate, fd, length);
}

static inline int sys_fsync(int fd) {
    return (int)_syscall1(__NR_fsync, fd);
}

static inline int sys_fdatasync(int fd) {
    return (int)_syscall1(__NR_fdatasync, fd);
}

static inline int sys_fadvise64(int fd, long offset, long len, int advice) {
    return (int)_syscall4(__NR_fadvise64, fd, offset, len, advice);
}

static inline int sys_unlinkat(int dirfd, const char *pathname, int flags) {
    return (int)_syscall3(__NR_unlinkat, dirfd, pathname, flags);
}

static inline int sys_clock_gettime(int clk_id,
                                     struct __kernel_timespec *tp) {
    return (int)_syscall2(__NR_clock_gettime, clk_id, tp);
}

static inline long sys_getrandom(void *buf, size_t buflen,
                                  unsigned int flags) {
    return _syscall3(__NR_getrandom, buf, buflen, flags);
}

static inline long sys_read(int fd, void *buf, size_t count) {
    return _syscall3(__NR_read, fd, buf, count);
}
