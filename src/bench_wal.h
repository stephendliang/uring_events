#pragma once
// bench_wal.h — WAL group commit and OLTP mixed benchmark structures.

#include "bench.h"
#include "bench_sqe.h"

// User data encoding for mixed-op CQE disambiguation.
// Bits 15-14: op type, Bits 13-0: slot index (max 16383)
#define WAL_OP_READ  0u
#define WAL_OP_WRITE 1u
#define WAL_OP_SYNC  2u

#define WAL_ENCODE_UD(type, slot) \
    ((u64)(((u32)(type) << 14) | ((u32)(slot) & 0x3FFF)))
#define WAL_DECODE_TYPE(ud) ((u32)(((ud) >> 14) & 0x3))
#define WAL_DECODE_SLOT(ud) ((u32)((ud) & 0x3FFF))

// SQE prep helpers with explicit user_data (unlike bench_sqe.h which
// hard-codes BENCH_ENCODE_UD).

static inline void wal_prep_write(struct io_uring_sqe *sqe,
                                   int fd, const void *buf, u32 len,
                                   u64 offset, u64 user_data,
                                   __kernel_rwf_t rw_flags) {
    mem_zero_cacheline(sqe);
    sqe->opcode    = IORING_OP_WRITE;
    sqe->fd        = fd;
    sqe->off       = offset;
    sqe->addr      = (u64)(uintptr_t)buf;
    sqe->len       = len;
    sqe->user_data = user_data;
    sqe->rw_flags  = rw_flags;
}

static inline void wal_prep_read(struct io_uring_sqe *sqe,
                                  int fd, void *buf, u32 len,
                                  u64 offset, u64 user_data,
                                  __kernel_rwf_t rw_flags) {
    mem_zero_cacheline(sqe);
    sqe->opcode    = IORING_OP_READ;
    sqe->fd        = fd;
    sqe->off       = offset;
    sqe->addr      = (u64)(uintptr_t)buf;
    sqe->len       = len;
    sqe->user_data = user_data;
    sqe->rw_flags  = rw_flags;
}

// WAL group commit config.
struct wal_config {
    enum io_mode mode;       // IO_BUFFERED or IO_DIRECT
    u32 group_size;          // writes per group commit (1..256)
    u32 record_size;         // bytes per write (512-aligned, 512..8192)
    u32 num_groups;          // total group commits to measure
    u32 file_size_mb;        // WAL file size (0 = auto)
    int cpu;
    const char *file_path;
};

// WAL result — dual latency distributions.
struct wal_result {
    u64 total_ns;
    u32 completed_groups, error_count;

    // Group commit latency: first write submit -> fdatasync complete
    u64 group_lat_min_ns, group_lat_max_ns, group_lat_avg_ns;
    u64 group_lat_p50_ns, group_lat_p99_ns, group_lat_p999_ns;

    // fdatasync-only latency
    u64 sync_lat_min_ns, sync_lat_max_ns, sync_lat_avg_ns;
    u64 sync_lat_p50_ns, sync_lat_p99_ns, sync_lat_p999_ns;

    // Derived
    u64 commits_per_sec, txns_per_sec, throughput_mbps;
};

// OLTP mixed benchmark config.
struct oltp_config {
    enum io_mode mode;
    u32 read_qd;             // read pipeline depth (default 32)
    u32 group_size;          // WAL writes per group (default 4)
    u32 record_size;         // WAL record size (default 512)
    u32 page_size;           // data page size (fixed 4096)
    u32 num_groups;          // total group commits (drives workload duration)
    u32 reads_per_commit;    // reads between group commits (default 32)
    u32 data_file_mb;        // data file size (default 2048)
    u32 wal_file_mb;         // WAL file size (0 = auto)
    int cpu;
    const char *data_path;
    const char *wal_path;
};

// OLTP result — separate read + WAL stats.
struct oltp_result {
    u64 total_ns;

    // Read stats
    u32 read_completed, read_errors;
    u64 read_lat_min_ns, read_lat_max_ns, read_lat_avg_ns;
    u64 read_lat_p50_ns, read_lat_p99_ns, read_lat_p999_ns;
    u64 read_iops, read_mbps;

    // WAL commit stats
    u32 wal_completed_groups, wal_errors;
    u64 group_lat_min_ns, group_lat_max_ns, group_lat_avg_ns;
    u64 group_lat_p50_ns, group_lat_p99_ns, group_lat_p999_ns;
    u64 sync_lat_min_ns, sync_lat_max_ns, sync_lat_avg_ns;
    u64 sync_lat_p50_ns, sync_lat_p99_ns, sync_lat_p999_ns;
    u64 commits_per_sec, txns_per_sec;
};

// Run WAL group commit benchmark.
int wal_run(const struct wal_config *cfg, struct wal_result *res);

// Run OLTP mixed benchmark.
int oltp_run(const struct oltp_config *cfg, struct oltp_result *res);
