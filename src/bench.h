#pragma once
// bench.h — Public interface for the io_uring disk I/O benchmark.

#include "nolibc.h"

enum io_mode {
    IO_BUFFERED  = 0,
    IO_DIRECT    = 1,
    IO_DONTCACHE = 2,
};

enum access_pattern {
    ACCESS_SEQ    = 0,
    ACCESS_RANDOM = 1,
};

enum io_direction {
    DIR_READ  = 0,
    DIR_WRITE = 1,
};

struct bench_config {
    enum io_mode mode;
    enum access_pattern pattern;
    enum io_direction direction;
    u32 block_size;       // 512, 4096, 65536, 1048576
    u32 queue_depth;      // SQEs in flight (default 64)
    u32 num_ops;          // Total ops (default 100000)
    u32 file_size_mb;     // Test file size (0 = auto)
    int cpu;              // CPU pin (-1 = no pin)
    const char *file_path;
};

struct bench_result {
    u64 total_ns;
    u64 total_bytes;
    u32 completed_ops;
    u32 error_count;
    u64 lat_min_ns;
    u64 lat_max_ns;
    u64 lat_avg_ns;
    u64 lat_p50_ns;
    u64 lat_p99_ns;
    u64 lat_p999_ns;
    u64 throughput_mbps;  // MB/s as integer
    u64 iops;             // I/O ops per second
};

// Run a single benchmark configuration. Returns 0 on success, negative errno on failure.
int bench_run(const struct bench_config *cfg, struct bench_result *res);
