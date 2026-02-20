// bench.c — io_uring disk I/O benchmark engine.
// Exercises buffered, O_DIRECT, and RWF_DONTCACHE paths.

#include "bench.h"
#include "bench_syscalls.h"
#include "bench_stats.h"
#include "bench_sqe.h"

// xoshiro256** PRNG — fast, good distribution, no libc dependency.
struct xoshiro256 {
    u64 s[4];
};

static inline u64 xoshiro_rotl(u64 x, int k) {
    return (x << k) | (x >> (64 - k));
}

static inline u64 xoshiro_next(struct xoshiro256 *state) {
    u64 *s = state->s;
    u64 result = xoshiro_rotl(s[1] * 5, 7) * 9;

    u64 t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = xoshiro_rotl(s[3], 45);

    return result;
}

static void xoshiro_seed(struct xoshiro256 *state) {
    sys_getrandom(state->s, sizeof(state->s), 0);
    // Ensure non-zero state
    if (state->s[0] == 0 && state->s[1] == 0 &&
        state->s[2] == 0 && state->s[3] == 0) {
        state->s[0] = 0xdeadbeefcafe1234ULL;
        state->s[1] = 0x0123456789abcdefULL;
        state->s[2] = 0xfedcba9876543210ULL;
        state->s[3] = 0x1234567890abcdefULL;
    }
}

// Fill file with pattern for read benchmarks (cold path).
static int bench_fill_file(int fd, u64 file_size, u32 block_size) {
    // Allocate a single block buffer
    void *buf = mmap(NULL, block_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(buf))
        return MMAP_ERR(buf);

    // Fill buffer with 0xAA pattern
    u8 *p = (u8 *)buf;
    for (u32 i = 0; i < block_size; i++)
        p[i] = 0xAA;

    u64 written = 0;
    while (written < file_size) {
        u32 chunk = block_size;
        if (file_size - written < chunk)
            chunk = (u32)(file_size - written);
        long ret = sys_write(fd, buf, chunk);
        if (ret < 0) {
            munmap(buf, block_size);
            return (int)ret;
        }
        written += (u64)ret;
    }

    munmap(buf, block_size);
    return sys_fsync(fd);
}

// Pre-generate random offset table.
static void bench_gen_offsets(u64 *offsets, u32 count, u64 file_size,
                               u32 block_size, enum access_pattern pattern) {
    if (pattern == ACCESS_SEQ) {
        u64 off = 0;
        for (u32 i = 0; i < count; i++) {
            offsets[i] = off;
            off += block_size;
            if (off + block_size > file_size)
                off = 0;
        }
    } else {
        struct xoshiro256 rng;
        xoshiro_seed(&rng);
        u64 max_blocks = file_size / block_size;
        for (u32 i = 0; i < count; i++) {
            u64 block_idx = xoshiro_next(&rng) % max_blocks;
            offsets[i] = block_idx * block_size;
        }
    }
}

// Submit a single I/O op into the given slot.
static inline int bench_submit_op(struct uring *ring, int fd,
                                   u8 *io_buf_base, u32 block_size,
                                   u64 offset, u32 slot,
                                   enum io_direction dir,
                                   __kernel_rwf_t rw_flags) {
    struct io_uring_sqe *sqe = uring_get_sqe(ring);
    if (unlikely(!sqe))
        return -ENOSPC;

    void *buf = io_buf_base + (u64)slot * block_size;

    if (dir == DIR_READ)
        bench_prep_read(sqe, fd, buf, block_size, offset, slot, rw_flags);
    else
        bench_prep_write(sqe, fd, buf, block_size, offset, slot, rw_flags);

    return 0;
}

// Run I/O loop (warmup or measured).
// If lat_out is NULL, latencies are discarded (warmup).
static int bench_io_loop(struct uring *ring, int fd, u8 *io_buf_base,
                          u32 block_size, u32 queue_depth, u32 num_ops,
                          u64 *offsets, enum io_direction dir,
                          __kernel_rwf_t rw_flags, u64 *lat_out,
                          u32 *completed_out, u32 *error_out) {
    u32 submitted = 0;
    u32 completed = 0;
    u32 errors = 0;
    u32 inflight = 0;

    // Per-slot start timestamps
    size_t ts_size = (size_t)queue_depth * sizeof(u64);
    u64 *start_ns = mmap(NULL, ts_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(start_ns))
        return MMAP_ERR(start_ns);

    // Prime the ring with initial submissions
    u32 prime = (num_ops < queue_depth) ? num_ops : queue_depth;
    for (u32 i = 0; i < prime; i++) {
        start_ns[i] = bench_now_ns();
        int ret = bench_submit_op(ring, fd, io_buf_base, block_size,
                                   offsets[submitted], i, dir, rw_flags);
        if (ret < 0) {
            munmap(start_ns, ts_size);
            return ret;
        }
        submitted++;
        inflight++;
    }

    struct __kernel_timespec ts = { .tv_sec = 5, .tv_nsec = 0 };
    struct uring_cq *cq = &ring->cq;

    while (completed < num_ops) {
        int ret = uring_submit_and_wait(ring, 1, &ts);
        if (ret < 0 && ret != -ETIME && ret != -EINTR) {
            munmap(start_ns, ts_size);
            return ret;
        }

        u32 head = smp_load_acquire(cq->khead);
        u32 tail = smp_load_acquire(cq->ktail);

        while (head != tail) {
            struct io_uring_cqe *cqe = &cq->cqes[head & cq->ring_mask];
            u64 now = bench_now_ns();
            u32 slot = BENCH_DECODE_SLOT(cqe->user_data);
            i32 res = cqe->res;

            if (likely(res >= 0)) {
                if (lat_out && completed < num_ops)
                    lat_out[completed] = now - start_ns[slot];
                completed++;
            } else {
                errors++;
                completed++;
            }

            // Resubmit into same slot if more ops remain
            if (submitted < num_ops) {
                start_ns[slot] = bench_now_ns();
                bench_submit_op(ring, fd, io_buf_base, block_size,
                                offsets[submitted], slot, dir, rw_flags);
                submitted++;
            } else {
                inflight--;
            }

            head++;
        }

        smp_store_release(cq->khead, head);

        if (inflight == 0 && submitted >= num_ops)
            break;
    }

    munmap(start_ns, ts_size);

    *completed_out = completed;
    *error_out = errors;
    return 0;
}

int bench_run(const struct bench_config *cfg, struct bench_result *res) {
    // Validate block_size for O_DIRECT
    if (cfg->mode == IO_DIRECT && cfg->block_size < 512)
        return -EINVAL;

    // CPU pin
    if (cfg->cpu >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cfg->cpu, &cpuset);
        sched_setaffinity(0, sizeof(cpuset), &cpuset);
    }

    // Compute file size
    u64 file_size;
    if (cfg->file_size_mb > 0) {
        file_size = (u64)cfg->file_size_mb * 1048576ULL;
    } else {
        // Auto: max(256MB, num_ops * block_size * 2) capped at 4GB
        u64 data_size = (u64)cfg->num_ops * cfg->block_size * 2;
        file_size = (data_size > 268435456ULL) ? data_size : 268435456ULL;
        if (file_size > 4294967296ULL)
            file_size = 4294967296ULL;
    }

    // Ensure file_size is aligned to block_size
    file_size = (file_size / cfg->block_size) * cfg->block_size;
    if (file_size < cfg->block_size)
        file_size = cfg->block_size;

    // Open file
    int open_flags = O_RDWR | O_CREAT;
    if (cfg->mode == IO_DIRECT)
        open_flags |= O_DIRECT;

    int fd = sys_openat(AT_FDCWD, cfg->file_path, open_flags, 0644);
    if (fd < 0)
        return fd;

    // Pre-allocate file
    int ret = sys_fallocate(fd, 0, 0, (long)file_size);
    if (ret < 0) {
        // fallocate may not be supported (e.g., tmpfs) — try ftruncate
        ret = sys_ftruncate(fd, (long)file_size);
        if (ret < 0) {
            sys_close(fd);
            return ret;
        }
    }

    // Fill file for read benchmarks (writes need content to avoid sparse reads)
    ret = bench_fill_file(fd, file_size, cfg->block_size);
    if (ret < 0) {
        sys_close(fd);
        return ret;
    }

    // Drop page cache for fair cold start
    sys_fadvise64(fd, 0, 0, POSIX_FADV_DONTNEED);

    // Init io_uring
    struct uring ring;
    u32 sq_entries = cfg->queue_depth * 2;
    if (sq_entries < 16) sq_entries = 16;
    u32 cq_entries = sq_entries * 2;

    ret = uring_init(&ring, sq_entries, cq_entries);
    if (ret < 0) {
        sys_close(fd);
        return ret;
    }

    // Allocate I/O buffers — page-aligned via MAP_ANONYMOUS (O_DIRECT safe)
    size_t buf_size = (size_t)cfg->queue_depth * cfg->block_size;
    u8 *io_buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(io_buf)) {
        ret = MMAP_ERR(io_buf);
        goto cleanup_ring;
    }

    // Fill write buffers with pattern
    if (cfg->direction == DIR_WRITE) {
        u8 *p = io_buf;
        for (size_t i = 0; i < buf_size; i++)
            p[i] = 0xBB;
    }

    // Total ops includes warmup
    u32 warmup_ops = cfg->num_ops / 10;
    if (warmup_ops < 1) warmup_ops = 1;
    u32 total_offsets = cfg->num_ops + warmup_ops;

    // Allocate offset table
    size_t off_size = (size_t)total_offsets * sizeof(u64);
    u64 *offsets = mmap(NULL, off_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(offsets)) {
        ret = MMAP_ERR(offsets);
        goto cleanup_buf;
    }
    bench_gen_offsets(offsets, total_offsets, file_size,
                       cfg->block_size, cfg->pattern);

    // Allocate latency array
    size_t lat_size = (size_t)cfg->num_ops * sizeof(u64);
    u64 *latencies = mmap(NULL, lat_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(latencies)) {
        ret = MMAP_ERR(latencies);
        goto cleanup_offsets;
    }

    // Determine rw_flags for this mode
    __kernel_rwf_t rw_flags = 0;
    if (cfg->mode == IO_DONTCACHE)
        rw_flags = RWF_DONTCACHE;

    // Phase 2: Warmup
    u32 warmup_completed = 0, warmup_errors = 0;

    // Drop cache before warmup for consistent state
    sys_fadvise64(fd, 0, 0, POSIX_FADV_DONTNEED);

    ret = bench_io_loop(&ring, fd, io_buf, cfg->block_size,
                         cfg->queue_depth, warmup_ops,
                         offsets, cfg->direction, rw_flags,
                         NULL, &warmup_completed, &warmup_errors);
    if (ret < 0)
        goto cleanup_lat;

    // Drop cache again before measured run (cold start for all modes)
    sys_fadvise64(fd, 0, 0, POSIX_FADV_DONTNEED);

    // Phase 3: Measured I/O
    u32 completed = 0, errors = 0;
    u64 t_start = bench_now_ns();

    ret = bench_io_loop(&ring, fd, io_buf, cfg->block_size,
                         cfg->queue_depth, cfg->num_ops,
                         offsets + warmup_ops, cfg->direction, rw_flags,
                         latencies, &completed, &errors);
    if (ret < 0)
        goto cleanup_lat;

    u64 t_end = bench_now_ns();

    // Phase 4: Optional fsync for writes
    if (cfg->direction == DIR_WRITE) {
        struct io_uring_sqe *sqe = uring_get_sqe(&ring);
        if (sqe) {
            bench_prep_fsync(sqe, fd);
            struct __kernel_timespec fsync_ts = { .tv_sec = 30, .tv_nsec = 0 };
            uring_submit_and_wait(&ring, 1, &fsync_ts);
            // Consume CQE
            u32 head = smp_load_acquire(ring.cq.khead);
            u32 tail = smp_load_acquire(ring.cq.ktail);
            if (head != tail)
                smp_store_release(ring.cq.khead, head + 1);
        }
    }

    // Phase 5: Compute stats
    u32 good_ops = completed - errors;
    res->total_ns = t_end - t_start;
    res->total_bytes = (u64)good_ops * cfg->block_size;
    res->completed_ops = completed;
    res->error_count = errors;

    if (good_ops > 0) {
        bench_sort_u64(latencies, good_ops);
        res->lat_min_ns  = latencies[0];
        res->lat_max_ns  = latencies[good_ops - 1];
        // Average: sum / count (use running average to avoid overflow)
        u64 avg = 0;
        for (u32 i = 0; i < good_ops; i++)
            avg += (latencies[i] - avg) / (i + 1);
        res->lat_avg_ns  = avg;
        res->lat_p50_ns  = bench_percentile(latencies, good_ops, 500);
        res->lat_p99_ns  = bench_percentile(latencies, good_ops, 990);
        res->lat_p999_ns = bench_percentile(latencies, good_ops, 999);

        // Throughput: (bytes * 1000) / total_ns = MB/s
        if (res->total_ns > 0) {
            res->throughput_mbps = (res->total_bytes * 1000ULL) /
                                   (res->total_ns);
            res->iops = ((u64)good_ops * 1000000000ULL) / res->total_ns;
        }
    }

    ret = 0;

cleanup_lat:
    munmap(latencies, lat_size);
cleanup_offsets:
    munmap(offsets, off_size);
cleanup_buf:
    munmap(io_buf, buf_size);
cleanup_ring:
    // Unregister ring fd if registered
    if (ring.registered_index >= 0) {
        struct io_uring_rsrc_update up = {
            .offset = (u32)ring.registered_index,
        };
        io_uring_register(ring.ring_fd, IORING_UNREGISTER_RING_FDS, &up, 1);
    }
    sys_close(ring.ring_fd);
    sys_close(fd);
    return ret;
}
