#define NOLIBC_MAIN

#include "core.h"
#include "bench.h"

// String comparison — byte-by-byte, no libc.
static inline int str_eq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

// Integer parsing (replicates main.c pattern).
static inline int parse_int(const char *str, int min, int max, const char *name) {
    long val = 0;
    const char *p = str;
    if (*p == '\0') goto bad;
    while (*p) {
        if (*p < '0' || *p > '9') goto bad;
        val = val * 10 + (*p - '0');
        if (val > max) goto bad;
        p++;
    }
    if (val < min) goto bad;
    return (int)val;
bad:
    _fmt_write(2, "[FATAL] Invalid %s: '%s' (must be %d-%d)\n", name, str, min, max);
    return -1;
}

// Mode names for display.
static const char *mode_name(enum io_mode m) {
    switch (m) {
    case IO_BUFFERED:  return "buffered";
    case IO_DIRECT:    return "direct";
    case IO_DONTCACHE: return "dontcache";
    }
    return "?";
}

static const char *dir_name(enum io_direction d) {
    return d == DIR_READ ? "read" : "write";
}

static const char *pat_name(enum access_pattern p) {
    return p == ACCESS_SEQ ? "seq" : "rand";
}

// Print a single result line (tab-separated for readability).
static void print_result(const struct bench_config *cfg,
                          const struct bench_result *res) {
    u64 avg_us = res->lat_avg_ns / 1000;
    u64 p50_us = res->lat_p50_ns / 1000;
    u64 p99_us = res->lat_p99_ns / 1000;
    u64 p999_us = res->lat_p999_ns / 1000;
    u64 min_us = res->lat_min_ns / 1000;

    _fmt_write(1, "%s\t%s\t%u\t%s\t", mode_name(cfg->mode),
               dir_name(cfg->direction), cfg->block_size,
               pat_name(cfg->pattern));
    _fmt_write(1, "%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t",
               res->throughput_mbps, res->iops,
               avg_us, p50_us, p99_us, p999_us, min_us);
    _fmt_write(1, "%u/%u\n",
               res->completed_ops - res->error_count,
               res->completed_ops);
}

// Print header for result table.
static void print_header(void) {
    sys_write(1, "Mode\tDir\tBlkSz\tPat\tMB/s\tIOPS\tAvg\tP50\tP99\tP999\tMin\tOK/Total\n", 59);
    sys_write(1, "----\t---\t-----\t---\t----\t----\t---\t---\t---\t----\t---\t--------\n", 59);
}

// Verbose single-test output.
static void print_result_verbose(const struct bench_config *cfg,
                                  const struct bench_result *res) {
    _fmt_write(1, "\n--- %s %s %u %s ---\n",
               mode_name(cfg->mode), dir_name(cfg->direction),
               cfg->block_size, pat_name(cfg->pattern));
    _fmt_write(1, "Completed: %u ops (%u errors)\n",
               res->completed_ops, res->error_count);
    _fmt_write(1, "Throughput: %lu MB/s  |  IOPS: %lu\n",
               res->throughput_mbps, res->iops);
    _fmt_write(1, "Latency (us): avg=%lu  p50=%lu  p99=%lu",
               res->lat_avg_ns / 1000, res->lat_p50_ns / 1000,
               res->lat_p99_ns / 1000);
    _fmt_write(1, "  p99.9=%lu  min=%lu  max=%lu\n",
               res->lat_p999_ns / 1000,
               res->lat_min_ns / 1000, res->lat_max_ns / 1000);
    _fmt_write(1, "Total: %lu ms  |  Data: %lu MB\n",
               res->total_ns / 1000000, res->total_bytes / 1048576);
}

static void usage(void) {
    _fmt_write(2, "Usage: bench <mode> <dir> <blksz> [pat] [qd] [ops] [mb] [cpu] [path]\n\n");
    _fmt_write(2, "  mode:   buffered | direct | dontcache\n");
    _fmt_write(2, "  dir:    read | write\n");
    _fmt_write(2, "  blksz:  bytes (512, 4096, 65536, 1048576)\n");
    _fmt_write(2, "  pat:    seq | rand          (default: seq)\n");
    _fmt_write(2, "  qd:     1-4096              (default: 64)\n");
    _fmt_write(2, "  ops:    1-10000000          (default: 100000)\n");
    _fmt_write(2, "  mb:     1-65536             (default: auto)\n");
    _fmt_write(2, "  cpu:    0-1023              (default: 0)\n");
    _fmt_write(2, "  path:   string              (default: /tmp/uring_bench.dat)\n\n");
    _fmt_write(2, "  bench matrix [path]         Run full test matrix\n");
}

// Run full test matrix.
static int run_matrix(const char *file_path) {
    static const u32 block_sizes[] = { 512, 4096, 65536, 1048576 };
    static const enum io_mode modes[] = { IO_BUFFERED, IO_DIRECT, IO_DONTCACHE };
    static const enum io_direction dirs[] = { DIR_READ, DIR_WRITE };
    static const enum access_pattern pats[] = { ACCESS_SEQ, ACCESS_RANDOM };

    _fmt_write(1, "io_uring disk I/O benchmark — full matrix\n");
    _fmt_write(1, "File: %s  |  QD=32  |  ops=10000\n\n", file_path);
    print_header();

    int total = 0, passed = 0, skipped = 0;

    for (u32 bi = 0; bi < 4; bi++) {
        for (u32 mi = 0; mi < 3; mi++) {
            for (u32 di = 0; di < 2; di++) {
                for (u32 pi = 0; pi < 2; pi++) {
                    struct bench_config cfg = {
                        .mode = modes[mi],
                        .direction = dirs[di],
                        .pattern = pats[pi],
                        .block_size = block_sizes[bi],
                        .queue_depth = 32,
                        .num_ops = 10000,
                        .file_size_mb = 0,
                        .cpu = 0,
                        .file_path = file_path,
                    };

                    total++;
                    struct bench_result res = {0};
                    int ret = bench_run(&cfg, &res);
                    if (ret < 0) {
                        // O_DIRECT on tmpfs returns EINVAL — skip gracefully
                        if (ret == -EINVAL && cfg.mode != IO_BUFFERED) {
                            _fmt_write(1, "%-9s  %-5s  %-7u  %-4s  (skipped: EINVAL — tmpfs?)\n",
                                       mode_name(cfg.mode),
                                       dir_name(cfg.direction),
                                       cfg.block_size,
                                       pat_name(cfg.pattern));
                            skipped++;
                            continue;
                        }
                        _fmt_write(2, "[ERROR] %s %s %u %s: error %d\n",
                                   mode_name(cfg.mode), dir_name(cfg.direction),
                                   cfg.block_size, pat_name(cfg.pattern), ret);
                        continue;
                    }
                    print_result(&cfg, &res);
                    passed++;
                }
            }
        }
    }

    _fmt_write(1, "\nTotal: %d tests  |  Passed: %d  |  Skipped: %d  |  Failed: %d\n",
               total, passed, skipped, total - passed - skipped);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage();
        return 1;
    }

    // Special: matrix mode
    if (str_eq(argv[1], "matrix")) {
        const char *path = (argc > 2) ? argv[2] : "/tmp/uring_bench.dat";
        return run_matrix(path);
    }

    if (argc < 3) {
        usage();
        return 1;
    }

    // Parse mode
    enum io_mode mode;
    if (str_eq(argv[1], "buffered"))       mode = IO_BUFFERED;
    else if (str_eq(argv[1], "direct"))    mode = IO_DIRECT;
    else if (str_eq(argv[1], "dontcache")) mode = IO_DONTCACHE;
    else {
        _fmt_write(2, "[FATAL] Unknown mode: '%s'\n", argv[1]);
        return 1;
    }

    // Parse direction
    enum io_direction direction;
    if (str_eq(argv[2], "read"))       direction = DIR_READ;
    else if (str_eq(argv[2], "write")) direction = DIR_WRITE;
    else {
        _fmt_write(2, "[FATAL] Unknown direction: '%s'\n", argv[2]);
        return 1;
    }

    // Parse block_size
    if (argc < 4) {
        _fmt_write(2, "[FATAL] block_size required\n");
        return 1;
    }
    int bs = parse_int(argv[3], 512, 16777216, "block_size");
    if (bs < 0) return 1;

    struct bench_config cfg = {
        .mode = mode,
        .direction = direction,
        .block_size = (u32)bs,
        .pattern = ACCESS_SEQ,
        .queue_depth = 64,
        .num_ops = 100000,
        .file_size_mb = 0,
        .cpu = 0,
        .file_path = "/tmp/uring_bench.dat",
    };

    // Optional args
    if (argc > 4) {
        if (str_eq(argv[4], "rand"))      cfg.pattern = ACCESS_RANDOM;
        else if (str_eq(argv[4], "seq"))   cfg.pattern = ACCESS_SEQ;
        else {
            _fmt_write(2, "[FATAL] Unknown pattern: '%s'\n", argv[4]);
            return 1;
        }
    }
    if (argc > 5) {
        int qd = parse_int(argv[5], 1, 4096, "queue_depth");
        if (qd < 0) return 1;
        cfg.queue_depth = (u32)qd;
    }
    if (argc > 6) {
        int ops = parse_int(argv[6], 1, 10000000, "num_ops");
        if (ops < 0) return 1;
        cfg.num_ops = (u32)ops;
    }
    if (argc > 7) {
        int mb = parse_int(argv[7], 0, 65536, "file_mb");
        if (mb < 0) return 1;
        cfg.file_size_mb = (u32)mb;
    }
    if (argc > 8) {
        int cpu = parse_int(argv[8], 0, 1023, "cpu");
        if (cpu < 0) return 1;
        cfg.cpu = cpu;
    }
    if (argc > 9) {
        cfg.file_path = argv[9];
    }

    _fmt_write(1, "io_uring disk I/O benchmark\n");
    _fmt_write(1, "  mode=%s  dir=%s  bs=%u  pat=%s  qd=%u  ops=%u  cpu=%d\n",
               mode_name(cfg.mode), dir_name(cfg.direction),
               cfg.block_size, pat_name(cfg.pattern),
               cfg.queue_depth, cfg.num_ops, cfg.cpu);
    _fmt_write(1, "  file=%s\n\n", cfg.file_path);

    struct bench_result res = {0};
    int ret = bench_run(&cfg, &res);
    if (ret < 0) {
        _fmt_write(2, "[FATAL] Benchmark failed: %d\n", ret);
        return 1;
    }

    print_result_verbose(&cfg, &res);
    return 0;
}
