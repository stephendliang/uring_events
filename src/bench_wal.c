// bench_wal.c — WAL group commit and OLTP mixed benchmark engine.
// Measures fdatasync-dominated workloads: the real cost of crash safety.

#include "bench_wal.h"
#include "bench_stats.h"

// --- xoshiro256** PRNG (duplicated from bench.c — static there) ---

struct xoshiro256_wal {
    u64 s[4];
};

static inline u64 xoshiro_rotl_wal(u64 x, int k) {
    return (x << k) | (x >> (64 - k));
}

static inline u64 xoshiro_next_wal(struct xoshiro256_wal *state) {
    u64 *s = state->s;
    u64 result = xoshiro_rotl_wal(s[1] * 5, 7) * 9;

    u64 t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = xoshiro_rotl_wal(s[3], 45);

    return result;
}

static void xoshiro_seed_wal(struct xoshiro256_wal *state) {
    sys_getrandom(state->s, sizeof(state->s), 0);
    if (state->s[0] == 0 && state->s[1] == 0 &&
        state->s[2] == 0 && state->s[3] == 0) {
        state->s[0] = 0xdeadbeefcafe1234ULL;
        state->s[1] = 0x0123456789abcdefULL;
        state->s[2] = 0xfedcba9876543210ULL;
        state->s[3] = 0x1234567890abcdefULL;
    }
}

// --- File fill (cold path) ---

static int wal_fill_file(int fd, u64 file_size, u8 pattern) {
    u32 chunk_size = 1048576;  // 1MB chunks
    void *buf = mmap(NULL, chunk_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(buf))
        return MMAP_ERR(buf);

    u8 *p = (u8 *)buf;
    for (u32 i = 0; i < chunk_size; i++)
        p[i] = pattern;

    u64 written = 0;
    while (written < file_size) {
        u32 chunk = chunk_size;
        if (file_size - written < chunk)
            chunk = (u32)(file_size - written);
        long ret = sys_write(fd, buf, chunk);
        if (ret < 0) {
            munmap(buf, chunk_size);
            return (int)ret;
        }
        written += (u64)ret;
    }

    munmap(buf, chunk_size);
    return sys_fsync(fd);
}

// --- Stats computation ---

static void wal_compute_lat_stats(u64 *lats, u32 count,
                                   u64 *out_min, u64 *out_max, u64 *out_avg,
                                   u64 *out_p50, u64 *out_p99, u64 *out_p999) {
    if (count == 0) {
        *out_min = *out_max = *out_avg = 0;
        *out_p50 = *out_p99 = *out_p999 = 0;
        return;
    }

    bench_sort_u64(lats, count);
    *out_min = lats[0];
    *out_max = lats[count - 1];

    u64 avg = 0;
    for (u32 i = 0; i < count; i++)
        avg += (lats[i] - avg) / (i + 1);
    *out_avg = avg;

    *out_p50  = bench_percentile(lats, count, 500);
    *out_p99  = bench_percentile(lats, count, 990);
    *out_p999 = bench_percentile(lats, count, 999);
}

// --- Next power of 2 ---

static inline u32 next_pow2(u32 v) {
    if (v == 0) return 1;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
}

// =====================================================================
// WAL group commit benchmark
// =====================================================================

int wal_run(const struct wal_config *cfg, struct wal_result *res) {
    // Validate
    if (cfg->group_size < 1 || cfg->group_size > 256)
        return -EINVAL;
    if (cfg->record_size < 512 || cfg->record_size > 8192)
        return -EINVAL;
    if (cfg->record_size & 511)
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
        u64 data_size = (u64)cfg->num_groups * cfg->group_size *
                        cfg->record_size * 4;
        file_size = (data_size > 268435456ULL) ? data_size : 268435456ULL;
        if (file_size > 4294967296ULL)
            file_size = 4294967296ULL;
    }
    // Align to record_size
    file_size = (file_size / cfg->record_size) * cfg->record_size;
    if (file_size < (u64)cfg->record_size)
        file_size = cfg->record_size;

    // Open WAL file
    int open_flags = O_RDWR | O_CREAT;
    if (cfg->mode == IO_DIRECT)
        open_flags |= O_DIRECT;

    int fd = sys_openat(AT_FDCWD, cfg->file_path, open_flags, 0644);
    if (fd < 0)
        return fd;

    // Pre-allocate
    int ret = sys_fallocate(fd, 0, 0, (long)file_size);
    if (ret < 0) {
        ret = sys_ftruncate(fd, (long)file_size);
        if (ret < 0) {
            sys_close(fd);
            return ret;
        }
    }

    // Fill with 0xAA
    ret = wal_fill_file(fd, file_size, 0xAA);
    if (ret < 0) {
        sys_close(fd);
        return ret;
    }
    sys_fadvise64(fd, 0, 0, POSIX_FADV_DONTNEED);

    // Init io_uring
    struct uring ring;
    u32 sq_entries = next_pow2(cfg->group_size + 2);
    if (sq_entries < 16) sq_entries = 16;
    u32 cq_entries = sq_entries * 2;

    ret = uring_init(&ring, sq_entries, cq_entries);
    if (ret < 0) {
        sys_close(fd);
        return ret;
    }

    // Write buffers
    size_t buf_size = (size_t)cfg->group_size * cfg->record_size;
    u8 *write_buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(write_buf)) {
        ret = MMAP_ERR(write_buf);
        goto cleanup_ring;
    }
    for (size_t i = 0; i < buf_size; i++)
        write_buf[i] = 0xBB;

    // Latency arrays
    size_t lat_size = (size_t)cfg->num_groups * sizeof(u64);
    u64 *group_lats = mmap(NULL, lat_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(group_lats)) {
        ret = MMAP_ERR(group_lats);
        goto cleanup_buf;
    }
    u64 *sync_lats = mmap(NULL, lat_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(sync_lats)) {
        ret = MMAP_ERR(sync_lats);
        goto cleanup_glats;
    }

    // Determine rw_flags
    __kernel_rwf_t rw_flags = 0;
    if (cfg->mode == IO_DONTCACHE)
        rw_flags = RWF_DONTCACHE;

    struct __kernel_timespec ts = { .tv_sec = 5, .tv_nsec = 0 };
    struct uring_cq *cq = &ring.cq;

    // --- Core WAL loop ---
    u64 wal_offset = 0;
    u32 completed_groups = 0;
    u32 errors = 0;

    u64 t_total_start = bench_now_ns();

    for (u32 g = 0; g < cfg->num_groups; g++) {
        u64 t_group = bench_now_ns();

        // Phase 1: submit group_size write SQEs
        for (u32 w = 0; w < cfg->group_size; w++) {
            struct io_uring_sqe *sqe = uring_get_sqe(&ring);
            if (unlikely(!sqe)) {
                errors++;
                goto next_group;
            }
            void *buf = write_buf + (size_t)w * cfg->record_size;
            wal_prep_write(sqe, fd, buf, cfg->record_size, wal_offset,
                           WAL_ENCODE_UD(WAL_OP_WRITE, w), rw_flags);
            wal_offset += cfg->record_size;
            if (wal_offset + cfg->record_size > file_size)
                wal_offset = 0;
        }

        // Submit and wait for all writes
        ret = uring_submit_and_wait(&ring, cfg->group_size, &ts);
        if (ret < 0 && ret != -ETIME && ret != -EINTR) {
            errors++;
            goto next_group;
        }

        // Drain write CQEs
        u32 write_cqes = 0;
        while (write_cqes < cfg->group_size) {
            u32 head = smp_load_acquire(cq->khead);
            u32 tail = smp_load_acquire(cq->ktail);
            while (head != tail && write_cqes < cfg->group_size) {
                struct io_uring_cqe *cqe = &cq->cqes[head & cq->ring_mask];
                if (cqe->res < 0) errors++;
                head++;
                write_cqes++;
            }
            smp_store_release(cq->khead, head);
            if (write_cqes < cfg->group_size) {
                ret = uring_submit_and_wait(&ring, 1, &ts);
                if (ret < 0 && ret != -ETIME && ret != -EINTR)
                    break;
            }
        }

        // Phase 2: fdatasync
        u64 t_sync = bench_now_ns();
        {
            struct io_uring_sqe *sqe = uring_get_sqe(&ring);
            if (unlikely(!sqe)) {
                errors++;
                goto next_group;
            }
            bench_prep_fdatasync(sqe, fd, WAL_ENCODE_UD(WAL_OP_SYNC, 0));
        }

        ret = uring_submit_and_wait(&ring, 1, &ts);
        if (ret < 0 && ret != -ETIME && ret != -EINTR) {
            errors++;
            goto next_group;
        }

        // Drain fdatasync CQE
        {
            u32 head = smp_load_acquire(cq->khead);
            u32 tail = smp_load_acquire(cq->ktail);
            while (head == tail) {
                ret = uring_submit_and_wait(&ring, 1, &ts);
                if (ret < 0 && ret != -ETIME && ret != -EINTR) break;
                head = smp_load_acquire(cq->khead);
                tail = smp_load_acquire(cq->ktail);
            }
            if (head != tail) {
                struct io_uring_cqe *cqe = &cq->cqes[head & cq->ring_mask];
                if (cqe->res < 0) errors++;
                smp_store_release(cq->khead, head + 1);
            }
        }

        u64 t_end = bench_now_ns();
        group_lats[g] = t_end - t_group;
        sync_lats[g] = t_end - t_sync;
        completed_groups++;
        continue;

    next_group:
        group_lats[g] = 0;
        sync_lats[g] = 0;
    }

    u64 t_total_end = bench_now_ns();

    // Compute results
    res->total_ns = t_total_end - t_total_start;
    res->completed_groups = completed_groups;
    res->error_count = errors;

    if (completed_groups > 0) {
        wal_compute_lat_stats(group_lats, completed_groups,
                              &res->group_lat_min_ns, &res->group_lat_max_ns,
                              &res->group_lat_avg_ns, &res->group_lat_p50_ns,
                              &res->group_lat_p99_ns, &res->group_lat_p999_ns);
        wal_compute_lat_stats(sync_lats, completed_groups,
                              &res->sync_lat_min_ns, &res->sync_lat_max_ns,
                              &res->sync_lat_avg_ns, &res->sync_lat_p50_ns,
                              &res->sync_lat_p99_ns, &res->sync_lat_p999_ns);

        if (res->total_ns > 0) {
            res->commits_per_sec = ((u64)completed_groups * 1000000000ULL) /
                                    res->total_ns;
            res->txns_per_sec = res->commits_per_sec * cfg->group_size;
            u64 total_bytes = (u64)completed_groups * cfg->group_size *
                              cfg->record_size;
            res->throughput_mbps = (total_bytes * 1000ULL) / res->total_ns;
        }
    }

    ret = 0;

    munmap(sync_lats, lat_size);
cleanup_glats:
    munmap(group_lats, lat_size);
cleanup_buf:
    munmap(write_buf, buf_size);
cleanup_ring:
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

// =====================================================================
// OLTP mixed benchmark
// =====================================================================

int oltp_run(const struct oltp_config *cfg, struct oltp_result *res) {
    // Validate
    if (cfg->read_qd < 1 || cfg->read_qd > 4096)
        return -EINVAL;
    if (cfg->group_size < 1 || cfg->group_size > 256)
        return -EINVAL;
    if (cfg->record_size < 512 || cfg->record_size > 8192)
        return -EINVAL;
    if (cfg->record_size & 511)
        return -EINVAL;
    if (cfg->page_size != 4096)
        return -EINVAL;
    if (cfg->reads_per_commit < 1)
        return -EINVAL;

    // CPU pin
    if (cfg->cpu >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cfg->cpu, &cpuset);
        sched_setaffinity(0, sizeof(cpuset), &cpuset);
    }

    // Data file size
    u64 data_file_size = (u64)cfg->data_file_mb * 1048576ULL;
    data_file_size = (data_file_size / cfg->page_size) * cfg->page_size;
    if (data_file_size < cfg->page_size)
        data_file_size = cfg->page_size;

    // WAL file size
    u64 wal_file_size;
    if (cfg->wal_file_mb > 0) {
        wal_file_size = (u64)cfg->wal_file_mb * 1048576ULL;
    } else {
        u64 ws = (u64)cfg->num_groups * cfg->group_size *
                 cfg->record_size * 4;
        wal_file_size = (ws > 268435456ULL) ? ws : 268435456ULL;
        if (wal_file_size > 4294967296ULL)
            wal_file_size = 4294967296ULL;
    }
    wal_file_size = (wal_file_size / cfg->record_size) * cfg->record_size;
    if (wal_file_size < (u64)cfg->record_size)
        wal_file_size = cfg->record_size;

    // Open data file
    int data_open_flags = O_RDWR | O_CREAT;
    if (cfg->mode == IO_DIRECT)
        data_open_flags |= O_DIRECT;

    int data_fd = sys_openat(AT_FDCWD, cfg->data_path, data_open_flags, 0644);
    if (data_fd < 0)
        return data_fd;

    // Open WAL file
    int wal_open_flags = O_RDWR | O_CREAT;
    if (cfg->mode == IO_DIRECT)
        wal_open_flags |= O_DIRECT;

    int wal_fd = sys_openat(AT_FDCWD, cfg->wal_path, wal_open_flags, 0644);
    if (wal_fd < 0) {
        sys_close(data_fd);
        return wal_fd;
    }

    int ret;

    // Pre-allocate data file
    ret = sys_fallocate(data_fd, 0, 0, (long)data_file_size);
    if (ret < 0) {
        ret = sys_ftruncate(data_fd, (long)data_file_size);
        if (ret < 0) goto cleanup_fds;
    }
    ret = wal_fill_file(data_fd, data_file_size, 0xAA);
    if (ret < 0) goto cleanup_fds;
    sys_fadvise64(data_fd, 0, 0, POSIX_FADV_DONTNEED);

    // Pre-allocate WAL file
    ret = sys_fallocate(wal_fd, 0, 0, (long)wal_file_size);
    if (ret < 0) {
        ret = sys_ftruncate(wal_fd, (long)wal_file_size);
        if (ret < 0) goto cleanup_fds;
    }
    ret = wal_fill_file(wal_fd, wal_file_size, 0xAA);
    if (ret < 0) goto cleanup_fds;
    sys_fadvise64(wal_fd, 0, 0, POSIX_FADV_DONTNEED);

    // Init io_uring
    struct uring ring;
    u32 sq_entries = next_pow2(cfg->read_qd + cfg->group_size + 2);
    if (sq_entries < 16) sq_entries = 16;
    u32 cq_entries = sq_entries * 2;

    ret = uring_init(&ring, sq_entries, cq_entries);
    if (ret < 0) goto cleanup_fds;

    // Read buffers (page-aligned for O_DIRECT)
    size_t read_buf_size = (size_t)cfg->read_qd * cfg->page_size;
    u8 *read_buf = mmap(NULL, read_buf_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(read_buf)) {
        ret = MMAP_ERR(read_buf);
        goto cleanup_ring;
    }

    // Write buffers
    size_t write_buf_size = (size_t)cfg->group_size * cfg->record_size;
    u8 *write_buf = mmap(NULL, write_buf_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(write_buf)) {
        ret = MMAP_ERR(write_buf);
        goto cleanup_rbuf;
    }
    for (size_t i = 0; i < write_buf_size; i++)
        write_buf[i] = 0xBB;

    // Per-slot read start timestamps
    size_t ts_size = (size_t)cfg->read_qd * sizeof(u64);
    u64 *read_start_ns = mmap(NULL, ts_size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(read_start_ns)) {
        ret = MMAP_ERR(read_start_ns);
        goto cleanup_wbuf;
    }

    // PRNG for random read offsets (generated on the fly, not pre-allocated).
    // Reads continue indefinitely until all groups complete — total count
    // is not known upfront because reads pipeline during write+sync phases.
    struct xoshiro256_wal rng;
    xoshiro_seed_wal(&rng);
    u64 max_pages = data_file_size / cfg->page_size;

    // Latency arrays — generous upper bound for reads
    u32 max_read_lats = cfg->num_groups * cfg->reads_per_commit * 4;
    if (max_read_lats < 1024) max_read_lats = 1024;
    size_t read_lat_size = (size_t)max_read_lats * sizeof(u64);
    u64 *read_lats = mmap(NULL, read_lat_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(read_lats)) {
        ret = MMAP_ERR(read_lats);
        goto cleanup_ts;
    }

    size_t wal_lat_size = (size_t)cfg->num_groups * sizeof(u64);
    u64 *group_lats = mmap(NULL, wal_lat_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(group_lats)) {
        ret = MMAP_ERR(group_lats);
        goto cleanup_rlats_oltp;
    }
    u64 *sync_lats = mmap(NULL, wal_lat_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(sync_lats)) {
        ret = MMAP_ERR(sync_lats);
        goto cleanup_glats_oltp;
    }

    // Determine rw_flags
    __kernel_rwf_t rw_flags = 0;
    if (cfg->mode == IO_DONTCACHE)
        rw_flags = RWF_DONTCACHE;

    struct __kernel_timespec timeout = { .tv_sec = 5, .tv_nsec = 0 };
    struct uring_cq *cq = &ring.cq;

    // --- OLTP state machine ---
    enum { WAL_IDLE, WAL_WRITING, WAL_SYNCING };

    u32 wal_state = WAL_IDLE;
    u64 wal_offset = 0;
    u32 groups_completed = 0;
    u32 reads_completed = 0;
    u32 read_errors = 0;
    u32 wal_errors = 0;
    u32 reads_since_commit = 0;
    u32 wal_writes_pending = 0;
    u64 group_start_ns = 0;
    u64 sync_start_ns = 0;

    u64 t_total_start = bench_now_ns();

    // Prime read pipeline
    for (u32 slot = 0; slot < cfg->read_qd; slot++) {
        struct io_uring_sqe *sqe = uring_get_sqe(&ring);
        if (unlikely(!sqe)) break;
        u64 off = (xoshiro_next_wal(&rng) % max_pages) * cfg->page_size;
        read_start_ns[slot] = bench_now_ns();
        void *buf = read_buf + (size_t)slot * cfg->page_size;
        wal_prep_read(sqe, data_fd, buf, cfg->page_size, off,
                      WAL_ENCODE_UD(WAL_OP_READ, slot), rw_flags);
    }

    // Main loop
    while (groups_completed < cfg->num_groups) {
        ret = uring_submit_and_wait(&ring, 1, &timeout);
        if (ret < 0 && ret != -ETIME && ret != -EINTR)
            break;

        u32 head = smp_load_acquire(cq->khead);
        u32 tail = smp_load_acquire(cq->ktail);

        while (head != tail) {
            struct io_uring_cqe *cqe = &cq->cqes[head & cq->ring_mask];
            u64 now = bench_now_ns();
            u32 type = WAL_DECODE_TYPE(cqe->user_data);
            u32 slot = WAL_DECODE_SLOT(cqe->user_data);
            i32 cqe_res = cqe->res;
            head++;

            if (type == WAL_OP_READ) {
                if (likely(cqe_res >= 0)) {
                    if (reads_completed < max_read_lats)
                        read_lats[reads_completed] = now - read_start_ns[slot];
                    reads_completed++;
                } else {
                    read_errors++;
                    reads_completed++;
                }
                reads_since_commit++;

                // Resubmit read — keep reads flowing until all groups done
                if (groups_completed < cfg->num_groups) {
                    struct io_uring_sqe *sqe = uring_get_sqe(&ring);
                    if (likely(sqe)) {
                        u64 off = (xoshiro_next_wal(&rng) % max_pages) *
                                  cfg->page_size;
                        read_start_ns[slot] = bench_now_ns();
                        void *buf = read_buf + (size_t)slot * cfg->page_size;
                        wal_prep_read(sqe, data_fd, buf, cfg->page_size, off,
                                      WAL_ENCODE_UD(WAL_OP_READ, slot),
                                      rw_flags);

                    }
                }

                // Trigger write group when enough reads
                if (wal_state == WAL_IDLE &&
                    reads_since_commit >= cfg->reads_per_commit) {
                    wal_state = WAL_WRITING;
                    group_start_ns = bench_now_ns();
                    reads_since_commit = 0;

                    for (u32 w = 0; w < cfg->group_size; w++) {
                        struct io_uring_sqe *sqe = uring_get_sqe(&ring);
                        if (unlikely(!sqe)) break;
                        void *buf = write_buf +
                                    (size_t)w * cfg->record_size;
                        wal_prep_write(sqe, wal_fd, buf,
                                       cfg->record_size, wal_offset,
                                       WAL_ENCODE_UD(WAL_OP_WRITE, w),
                                       rw_flags);
                        wal_offset += cfg->record_size;
                        if (wal_offset + cfg->record_size > wal_file_size)
                            wal_offset = 0;
                    }
                    wal_writes_pending = cfg->group_size;
                }

            } else if (type == WAL_OP_WRITE) {
                if (cqe_res < 0) wal_errors++;
                if (wal_writes_pending > 0) wal_writes_pending--;
                if (wal_writes_pending == 0 && wal_state == WAL_WRITING) {
                    // All writes done -> submit fdatasync
                    wal_state = WAL_SYNCING;
                    sync_start_ns = bench_now_ns();
                    struct io_uring_sqe *sqe = uring_get_sqe(&ring);
                    if (likely(sqe)) {
                        bench_prep_fdatasync(sqe, wal_fd,
                                             WAL_ENCODE_UD(WAL_OP_SYNC, 0));
                    }
                }

            } else if (type == WAL_OP_SYNC) {
                if (cqe_res < 0) wal_errors++;
                u64 now_sync = bench_now_ns();
                if (groups_completed < cfg->num_groups) {
                    group_lats[groups_completed] = now_sync - group_start_ns;
                    sync_lats[groups_completed] = now_sync - sync_start_ns;
                }
                groups_completed++;
                wal_state = WAL_IDLE;

                // Reads may have accumulated during write+sync phase.
                // Check if we can immediately trigger the next group.
                if (groups_completed < cfg->num_groups &&
                    reads_since_commit >= cfg->reads_per_commit) {
                    wal_state = WAL_WRITING;
                    group_start_ns = bench_now_ns();
                    reads_since_commit = 0;

                    for (u32 w = 0; w < cfg->group_size; w++) {
                        struct io_uring_sqe *sqe = uring_get_sqe(&ring);
                        if (unlikely(!sqe)) break;
                        void *buf = write_buf +
                                    (size_t)w * cfg->record_size;
                        wal_prep_write(sqe, wal_fd, buf,
                                       cfg->record_size, wal_offset,
                                       WAL_ENCODE_UD(WAL_OP_WRITE, w),
                                       rw_flags);
                        wal_offset += cfg->record_size;
                        if (wal_offset + cfg->record_size > wal_file_size)
                            wal_offset = 0;
                    }
                    wal_writes_pending = cfg->group_size;
                }
            }
        }

        smp_store_release(cq->khead, head);
    }

    u64 t_total_end = bench_now_ns();

    // Compute results
    res->total_ns = t_total_end - t_total_start;

    // Read stats
    u32 good_reads = reads_completed - read_errors;
    res->read_completed = reads_completed;
    res->read_errors = read_errors;
    if (good_reads > 0) {
        u32 lat_count = (good_reads < max_read_lats) ? good_reads : max_read_lats;
        wal_compute_lat_stats(read_lats, lat_count,
                              &res->read_lat_min_ns, &res->read_lat_max_ns,
                              &res->read_lat_avg_ns, &res->read_lat_p50_ns,
                              &res->read_lat_p99_ns, &res->read_lat_p999_ns);
        if (res->total_ns > 0) {
            res->read_iops = ((u64)good_reads * 1000000000ULL) / res->total_ns;
            res->read_mbps = ((u64)good_reads * cfg->page_size * 1000ULL) /
                             res->total_ns;
        }
    }

    // WAL stats
    res->wal_completed_groups = groups_completed;
    res->wal_errors = wal_errors;
    if (groups_completed > 0) {
        wal_compute_lat_stats(group_lats, groups_completed,
                              &res->group_lat_min_ns, &res->group_lat_max_ns,
                              &res->group_lat_avg_ns, &res->group_lat_p50_ns,
                              &res->group_lat_p99_ns, &res->group_lat_p999_ns);
        wal_compute_lat_stats(sync_lats, groups_completed,
                              &res->sync_lat_min_ns, &res->sync_lat_max_ns,
                              &res->sync_lat_avg_ns, &res->sync_lat_p50_ns,
                              &res->sync_lat_p99_ns, &res->sync_lat_p999_ns);
        if (res->total_ns > 0) {
            res->commits_per_sec = ((u64)groups_completed * 1000000000ULL) /
                                    res->total_ns;
            res->txns_per_sec = res->commits_per_sec * cfg->group_size;
        }
    }

    ret = 0;

    munmap(sync_lats, wal_lat_size);
cleanup_glats_oltp:
    munmap(group_lats, wal_lat_size);
cleanup_rlats_oltp:
    munmap(read_lats, read_lat_size);
cleanup_ts:
    munmap(read_start_ns, ts_size);
cleanup_wbuf:
    munmap(write_buf, write_buf_size);
cleanup_rbuf:
    munmap(read_buf, read_buf_size);
cleanup_ring:
    if (ring.registered_index >= 0) {
        struct io_uring_rsrc_update up = {
            .offset = (u32)ring.registered_index,
        };
        io_uring_register(ring.ring_fd, IORING_UNREGISTER_RING_FDS, &up, 1);
    }
    sys_close(ring.ring_fd);
cleanup_fds:
    sys_close(wal_fd);
    sys_close(data_fd);
    return ret;
}
