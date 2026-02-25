# Bench Suite

Documentation for the disk I/O benchmark binary (`bench`) and the standalone connection-tracking microbenchmark (`bench-conn`).

## Overview

The bench suite is a **separate binary** from the HTTP server. It shares `uring.c` for ring initialization (same setup flags) and `nolibc.h` / `core.h` / `util.h` for the freestanding runtime, but has its own `main()` in `bench_main.c` and its own SQE prep layer in `bench_sqe.h`.

Seven CLI modes cover disk I/O profiling from single-parameter tests to multi-run statistical sweeps.

## Build

```bash
make bench          # -O3 -march=native → ./bench
make bench-debug    # -O0 -g -DDEBUG → ./bench-debug
make bench-icx      # Intel ICX compiler → ./bench-icx
make bench-conn     # standalone microbenchmark → ./bench-conn
```

Source files compiled into `bench`: `bench_main.c`, `bench.c`, `bench_wal.c`, `uring.c`.

`bench-conn` is compiled from `bench_conn.c` alone (only depends on `core.h` → `nolibc.h`).

## Usage

### Single test

```bash
bench <mode> <dir> <blksz> [pat] [qd] [ops] [mb] [cpu] [path]
```

- **mode**: `buffered` | `direct` | `dontcache`
- **dir**: `read` | `write`
- **blksz**: block size in bytes (512, 4096, 65536, 1048576, ...)
- **pat**: `seq` | `rand` (default: `seq`)
- **qd**: queue depth 1-4096 (default: 64)
- **ops**: total I/O ops 1-10M (default: 100000)
- **mb**: file size in MB, 0=auto (default: auto)
- **cpu**: CPU pin 0-1023 (default: 0)
- **path**: test file path (default: `/tmp/uring_bench.dat`)

Example: `bench direct read 4096 rand 128 500000 2048 4 /data/test.dat`

### Matrix

```bash
bench matrix [path]
```

Runs all combinations of 4 block sizes x 3 modes x 2 directions x 2 patterns (48 tests). QD=32, 10K ops each. Tab-separated output.

### Sweep

```bash
bench sweep [qd] [mb] [path]
```

Buffered vs O_DIRECT across 14 block sizes (512B-4MB), 2 directions, 2 patterns. 112 tests total. Pre-fills the file once, then runs all tests with `skip_fill=1`. CSV output on stdout, progress on stderr.

### WAL group commit

```bash
bench wal [gs] [rs] [mode] [groups] [mb] [cpu] [path]
```

- **gs**: group size 1-256 (writes per commit, default: 4)
- **rs**: record size 512-8192 (default: 512)
- **mode**: `buffered` | `direct` (default: `buffered`)
- **groups**: total group commits (default: 10000)

Measures fdatasync-dominated workloads. Each group: submit N writes → wait for all → fdatasync → next group. Reports dual latency distributions (group and sync-only).

### WAL sweep

```bash
bench wal-sweep [cpu] [path]
```

40 tests: 5 group sizes x 4 record sizes x 2 modes. CSV output.

### OLTP mixed

```bash
bench oltp [rqd] [gs] [rs] [mode] [groups] [rpc] [dmb] [wmb] [cpu] [dpath] [wpath]
```

- **rqd**: read queue depth (default: 32)
- **rpc**: reads per commit trigger (default: 32)

Concurrent random reads + triggered WAL group commits. Reads pipeline continuously; every `rpc` completed reads triggers a write group + fdatasync. Reports separate read and WAL stats.

### OLTP sweep

```bash
bench oltp-sweep [runs] [cpu] [data_path] [wal_path]
```

- **runs**: measured runs per config, 3-30 (default: 20)

Sweeps `rpc={1,2,4,8,16,32,64,128}` x `gs={1,4}` x `{buffered,direct}` = 32 configs. Each config: 2 warmup runs + N measured runs. Reports mean and 95% confidence interval for each metric. CSV output.

## Architecture

### Shared Infrastructure

**Ring init.** `bench.c` and `bench_wal.c` call `uring_init()` from `uring.c` — same setup flags as the server (SUBMIT_ALL, SINGLE_ISSUER, DEFER_TASKRUN, CQSIZE, NO_SQARRAY). SQ/CQ sizes are scaled per benchmark: `sq = max(qd*2, 16)`, `cq = sq*2`.

**Statistics** (`bench_stats.h`). `bench_now_ns()` uses `sys_clock_gettime(CLOCK_MONOTONIC)` (~20ns overhead). Shell sort (`bench_sort_u64`) with Ciura gap sequence — O(n^1.25), no extra memory, good enough for latency arrays up to ~10M entries. `bench_percentile()` extracts p50/p99/p99.9 from sorted arrays. `bench_compute_ci()` computes 95% confidence intervals using t-distribution critical values (pre-tabulated for n=3..30) and integer square root.

**Syscalls** (`bench_syscalls.h`). File I/O syscalls (`openat`, `fallocate`, `ftruncate`, `fsync`, `fdatasync`, `fadvise64`, `getrandom`, `read`) kept separate from `nolibc.h` so the server binary doesn't link unused wrappers.

### bench.c — Slot-Based I/O Loop

`bench_run()` orchestrates a single benchmark run:

1. **File setup.** Open with `O_DIRECT` if direct mode. `fallocate` (or `ftruncate` fallback). Fill with 0xAA pattern. Drop page cache via `POSIX_FADV_DONTNEED`.

2. **Offset table.** Pre-generate all offsets. Sequential: linear walk with wrap. Random: xoshiro256** PRNG seeded from `getrandom()`. Offsets cover warmup + measured ops.

3. **I/O buffers.** `mmap(MAP_ANONYMOUS | MAP_POPULATE)` — page-aligned, which satisfies O_DIRECT alignment requirements without explicit alignment logic.

4. **Warmup phase.** 10% of total ops, latencies discarded. Cache drop before warmup.

5. **Measured phase.** Cache drop again for cold start. `bench_io_loop()` runs the slot-based I/O loop:

   - **Prime:** submit `min(num_ops, queue_depth)` initial ops, one per slot.
   - **Main loop:** `uring_submit_and_wait(1)` → drain CQEs → for each completion, record latency and resubmit into the same slot if more ops remain.
   - Each slot has a start timestamp (`start_ns[slot]`). Latency = `now - start_ns[slot]`.
   - On completion, the slot is immediately resubmitted with the next offset, keeping the ring full.

6. **Post-write fsync.** If direction is write, submit an `IORING_OP_FSYNC` and wait.

7. **Stats.** Sort latencies, compute min/max/avg/p50/p99/p99.9, throughput (MB/s), IOPS.

**Three I/O modes:**
- `IO_BUFFERED` — normal buffered I/O
- `IO_DIRECT` — `O_DIRECT` flag on open (bypasses page cache, requires alignment)
- `IO_DONTCACHE` — buffered I/O + `RWF_DONTCACHE` per-op flag (kernel 6.16+, pages evicted after I/O)

**Two access patterns:**
- `ACCESS_SEQ` — sequential offsets, wrapping at file end
- `ACCESS_RANDOM` — random block-aligned offsets via xoshiro256**

### bench_wal.c — WAL and OLTP

**WAL group commit** (`wal_run`). Synchronous group commit: submit N write SQEs → `submit_and_wait(N)` → drain all write CQEs → submit `IORING_OP_FSYNC` with `IORING_FSYNC_DATASYNC` → wait → drain. Repeat for each group. Measures two latency distributions: group (first write to sync complete) and sync-only (fsync submit to complete).

**OLTP mixed** (`oltp_run`). A state machine drives concurrent reads + triggered WAL batches on a single io_uring:

```
State: WAL_IDLE → WAL_WRITING → WAL_SYNCING → WAL_IDLE
```

- **Reads pipeline continuously.** `read_qd` slots are primed at startup. Each read completion resubmits immediately (random offset from xoshiro256**). Reads never stop while groups remain.
- **WAL trigger.** When `reads_since_commit >= reads_per_commit` and `wal_state == WAL_IDLE`, transition to WAL_WRITING. Submit `group_size` write SQEs.
- **WAL_WRITING → WAL_SYNCING.** When all write CQEs drain, submit fdatasync.
- **WAL_SYNCING → WAL_IDLE.** On sync CQE, record group/sync latency, increment `groups_completed`. If reads have accumulated during write+sync, immediately trigger next group.

Two files: data file (random reads) and WAL file (sequential writes with wrap). Both can be O_DIRECT.

### User_data Encoding

**bench.c:** `BENCH_ENCODE_UD(slot)` — 16-bit slot index in low bits. `BENCH_DECODE_SLOT(ud) = ud & 0xFFFF`. Simple: only one op type (read or write) in flight at a time.

**bench_wal.c:** `WAL_ENCODE_UD(type, slot)` — 2-bit op type in bits 15-14, 14-bit slot in bits 13-0. Op types: `WAL_OP_READ=0`, `WAL_OP_WRITE=1`, `WAL_OP_SYNC=2`. Needed because the OLTP loop has reads, writes, and fsyncs in flight simultaneously.

### Buffer Management

All I/O buffers are `mmap(MAP_ANONYMOUS | MAP_POPULATE)` — page-aligned (satisfies O_DIRECT without explicit alignment), pre-faulted, zero-initialized by kernel. Slot-indexed: `buf = io_buf_base + slot * block_size`.

The bench does **not** use the server's provided buffer ring. Each op uses a fixed buffer at a fixed address, indexed by slot number. No buffer recycle mechanism needed.

## bench_conn

Standalone microbenchmark in `src/bench_conn.c`. **Not io_uring-based** — pure CPU benchmark measuring connection idle-tracking strategies.

```bash
bench-conn [cpu]
```

Compares three strategies at {1K, 10K, 100K, 500K, 1M} active connections:

**Sieve (CLOCK):** `u8 flags[]` + bit-packed `u8 accessed[]` (1.125 bytes/conn). Touch sets accessed bit. Sweep processes 8 connections per byte read: if all 8 bits set, clear and skip (common case). Only checks flags for fds whose accessed bit was clear.

**Linear:** `u8 flags[]` + `u64 activity[]` (9 bytes/conn). Touch writes rdtsc timestamp. Sweep does O(N) sequential scan comparing `now - activity[fd] > timeout`.

**Wheel:** `u8 flags[]` + `u8 epoch[]` (2 bytes/conn). Touch writes `(u8)(rdtsc >> shift)`. Sweep does O(N) sequential scan with `(u8)(now_epoch - epoch[fd]) > TIMEOUT_EPOCHS`. Shift calibrated from TSC frequency for ~2s buckets.

**Benchmarks:** Two tests per strategy — touch (random fd, measured in cycles/op) and sweep (50% expired, measured in cycles per full sweep). Warmup + measured phases with RDTSC timing.

Results showed timing wheel is the Pareto winner: tied with linear for touch cost, fastest sweep, smallest footprint after sieve. See `docs/roadmap.md` section 2 for detailed numbers and the planned LRU-to-wheel migration.

## Files

| File | Purpose |
|------|---------|
| `src/bench_main.c` | Entry point, CLI parsing, all 7 modes, result formatting |
| `src/bench.c` | Disk I/O engine: slot-based I/O loop, file setup, stats |
| `src/bench_wal.c` | WAL group commit (`wal_run`) and OLTP mixed (`oltp_run`) |
| `src/bench_conn.c` | Standalone idle-tracking microbenchmark (sieve/linear/wheel) |
| `src/bench.h` | Config/result structs, enums (io_mode, access_pattern, io_direction) |
| `src/bench_wal.h` | WAL/OLTP config/result structs, WAL user_data encoding, SQE prep helpers |
| `src/bench_sqe.h` | Scalar SQE prep for bench (BENCH_ENCODE_UD, read/write/fsync) |
| `src/bench_stats.h` | Timing (clock_gettime), shell sort, percentiles, CI computation |
| `src/bench_syscalls.h` | File I/O syscalls (openat, fallocate, fadvise64, getrandom, ...) |

## Relationship to Docs

- `docs/oltp-sweep.md` — analysis of one `oltp-sweep` run (buffered vs O_DIRECT fdatasync)
- `sweep.csv` — raw CSV data from a `bench sweep` run
- `docs/roadmap.md` section 2 — `bench_conn` results driving the planned LRU-to-wheel migration
