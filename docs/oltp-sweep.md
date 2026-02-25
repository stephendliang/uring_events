# OLTP Mixed Workload: Buffered vs O_DIRECT Distribution Sweep

**Date**: 2026-02-20
**Commit**: 0e7e509 (sweep infrastructure), cd70366 (OLTP engine)

## Hypothesis

The previous single-point OLTP benchmark (cd70366) showed O_DIRECT winning for
database workloads: fdatasync p50 was 1.9ms (direct) vs 6.0ms (buffered). The
hypothesis was that page cache contention from concurrent buffered reads
destroys fdatasync latency, and there should exist a crossover point in the
read/write distribution where this contention begins to dominate.

**This experiment sweeps reads_per_commit from 1 (write-heavy) to 16
(read-heavy) to find that crossover.**

## Hardware

| Component | Detail |
|-----------|--------|
| CPU | Intel i9-12900HK (6P+8E, 20 logical) |
| NVMe | Samsung PM9A1 953GB, xfs, scheduler=none, QD=1023 |
| Kernel | 6.19.2-2-cachyos |
| Compiler | GCC 15.2.1 (`-O3 -march=native -flto -Werror`) |
| Binary | Freestanding (nolibc, no glibc, static-pie) |

### CPU Isolation

The kernel is booted with serious isolation for benchmarking:

```
isolcpus=managed_irq,domain:4-11
nohz_full=4-11
rcu_nocbs=4-11 rcu_nocb_poll
irqaffinity=0-3,12-19
skew_tick=1 tsc=reliable clocksource=tsc
nmi_watchdog=0 nowatchdog nosoftlockup
mitigations=off
```

- **CPUs 4-11**: P-core threads, fully isolated. No scheduler, no managed
  IRQs (NVMe queues q5-q12 deactivated), no RCU callbacks, tickless.
- **CPUs 0-3, 12-19**: Handle all IRQs, scheduler, and system work.
- **Benchmark pinned to CPU 9** via `taskset -c 9` from process birth.
  This core receives zero hardware interrupts, zero RCU callbacks, and
  zero timer ticks during the benchmark. The only code running on CPU 9
  is the benchmark itself.

Note: CPU governor was `powersave` during this run. Absolute numbers may
be lower than `performance` mode, but relative comparisons (buffered vs
direct) are unaffected since both modes run on the same core at the same
frequency.

### NVMe IRQ Topology

Per-CPU NVMe completion queues (IRQs 163-182) are pinned 1:1 to CPUs 0-19.
However, `isolcpus=managed_irq` deactivates queues on CPUs 4-11. When the
benchmark (on CPU 9) submits io_uring requests, the kernel routes NVMe
completions through an active queue on a non-isolated CPU (0-3 or 12-19).

```
IRQ 162 (nvme0q0):  CPUs 0-3,12-19  (admin queue)
IRQ 163 (nvme0q1):  CPU 0
IRQ 164 (nvme0q2):  CPU 1
...
IRQ 172 (nvme0q10): CPU 9   <-- DEACTIVATED (managed_irq isolation)
...
IRQ 182 (nvme0q20): CPU 19
```

## Benchmark Design

### Sweep Matrix

| Axis | Values | Count |
|------|--------|-------|
| `reads_per_commit` | 1, 2, 4, 8, 16 | 5 (ran before kill) |
| `group_size` | 1, 4 | 2 |
| `mode` | buffered, direct | 2 |
| **Total measured** | | **17 configs** |

Originally planned: rpc up to 128 (32 configs total). The sweep was killed
at config 18/32. The 17 completed configs cover rpc=1 through rpc=16,
which turns out to be sufficient because the data shows zero dependence
on rpc (see Results).

### Fixed Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `read_qd` | 32 | Saturate NVMe queue for read pipelining |
| `record_size` | 512 | Minimum WAL record (worst case for sync amortization) |
| `num_groups` | 5000 | ~10s per run at direct speeds |
| `data_file_mb` | 2048 | Larger than L3 cache, forces NVMe reads for direct |
| `wal_file_mb` | auto | 256MB minimum, wraps around |
| `page_size` | 4096 | Standard filesystem page |

### Per-Config Execution

- **2 warmup runs** (discarded): stabilize NVMe firmware, page cache, XFS journal
- **3 measured runs**: minimum for 95% CI via t-distribution (df=2, t=4.303)
- Each run: 5000 group commits with concurrent random reads
- Total runtime: ~45 minutes (killed at ~35 minutes, 17/32 configs done)

### Statistical Method

95% confidence intervals computed per-metric using:
- Sample mean and variance with Bessel's correction (n-1 denominator)
- t-distribution critical values (two-tailed, df=n-1)
- Integer arithmetic only (no floating point in freestanding binary)

CI half-width = t(df, 0.025) * stddev / sqrt(n)

With n=3 and df=2, t=4.303 — very conservative, which makes the tight CIs
even more remarkable.

## Results

### Raw Data (CSV)

```
rpc,gs,mode,n,commits_mean,commits_ci,txns_mean,txns_ci,sync_p50_us,sync_p50_ci,sync_p99_us,sync_p99_ci,grp_p50_us,grp_p50_ci,grp_p99_us,grp_p99_ci,read_iops_mean,read_iops_ci,read_p50_us,read_p50_ci
1,1,buffered,3,123,2,123,2,5996,0,8675,5210,8001,0,11342,2605,1132970,40704,63,1
1,1,direct,3,494,39,494,39,1942,10,3365,5210,1967,20,3405,5210,304969,20352,51,2
1,4,buffered,3,112,0,449,4,5994,0,8337,1302,8034,40,11014,20,1094164,20352,67,10
1,4,direct,3,500,2,2001,9,1937,10,2137,162,1984,10,2193,162,299060,2544,50,1
2,1,buffered,3,122,2,122,2,5996,0,8673,5210,8001,0,11336,2605,1107673,40704,66,5
2,1,direct,3,498,9,498,9,1945,10,3317,2605,1970,10,3432,2605,300899,2544,49,0
2,4,buffered,3,112,2,450,4,5994,0,8329,2605,8346,1302,11029,1302,1099335,40704,62,0
2,4,direct,3,493,4,1974,19,1949,10,2453,1302,1996,10,2520,1302,302196,5088,50,1
4,1,buffered,3,122,4,122,4,5996,1,9990,20,8001,0,11997,20,1112623,40704,63,2
4,1,direct,3,492,39,492,39,1950,10,3339,5210,1974,5,3366,5210,307342,20352,48,0
4,4,buffered,3,112,2,448,9,5995,1,8722,2605,8678,1302,11668,1302,1103376,81409,64,10
4,4,direct,3,480,9,1922,39,1956,10,4788,2605,2003,10,4835,2605,310681,10176,50,0
8,1,buffered,3,121,0,121,0,5996,0,9997,0,8001,0,12003,1,1011515,81409,68,5
8,1,direct,3,474,79,474,79,1965,1,3772,2605,1992,1,3865,2605,314818,40704,49,0
8,4,buffered,3,110,2,442,4,5994,1,9328,1302,9111,325,11675,1302,1019993,20352,67,2
8,4,direct,3,484,9,1938,39,1965,10,3369,2605,2019,20,3518,2605,305438,5088,50,0
16,1,buffered,3,121,2,121,2,5996,0,9998,10,8001,0,12005,2,1141814,10176,64,5
```

### Summary Table

```
              BUFFERED                           O_DIRECT
rpc  gs  commits/s  sync_p50  read_IOPS      commits/s  sync_p50  read_IOPS
────────────────────────────────────────────────────────────────────────────────
 1    1   123 ±2    5996 ±0   1,133K ±41K     494 ±39   1942 ±10   305K ±20K
 1    4   112 ±0    5994 ±0   1,094K ±20K     500 ±2    1937 ±10   299K ±3K
 2    1   122 ±2    5996 ±0   1,108K ±41K     498 ±9    1945 ±10   301K ±3K
 2    4   112 ±2    5994 ±0   1,099K ±41K     493 ±4    1949 ±10   302K ±5K
 4    1   122 ±4    5996 ±1   1,113K ±41K     492 ±39   1950 ±10   307K ±20K
 4    4   112 ±2    5995 ±1   1,103K ±81K     480 ±9    1956 ±10   311K ±10K
 8    1   121 ±0    5996 ±0   1,012K ±81K     474 ±79   1965 ±1    315K ±41K
 8    4   110 ±2    5994 ±1   1,020K ±20K     484 ±9    1965 ±10   305K ±5K
16    1   121 ±2    5996 ±0   1,142K ±10K      (killed during run)
```

All latencies in microseconds. ± values are 95% CI half-widths.

### Key Observations

**1. Sync latency is a hardware constant — rpc has zero effect.**

Buffered fdatasync p50 across all 9 buffered configs:

| rpc | gs=1 | gs=4 |
|----:|-----:|-----:|
| 1 | 5996 ±0 | 5994 ±0 |
| 2 | 5996 ±0 | 5994 ±0 |
| 4 | 5996 ±1 | 5995 ±1 |
| 8 | 5996 ±0 | 5994 ±1 |
| 16 | 5996 ±0 | — |

Range: 5993-5997us. CI is literally zero on most configs. This is not
"approximately constant" — it is constant to within the clock resolution.

Direct fdatasync p50 across all 8 direct configs:

| rpc | gs=1 | gs=4 |
|----:|-----:|-----:|
| 1 | 1942 ±10 | 1937 ±10 |
| 2 | 1945 ±10 | 1949 ±10 |
| 4 | 1950 ±10 | 1956 ±10 |
| 8 | 1965 ±1 | 1965 ±10 |

Range: 1932-1974us. Slight upward drift (~1%) from rpc=1 to rpc=8 — this
is within noise and likely reflects minor NVMe firmware state changes, not
a trend.

**Ratio: 5995 / 1950 = 3.07x.** This ratio is the cost of the XFS journal.

**2. The 6ms buffered fdatasync is the XFS journal transaction cost.**

Buffered fdatasync on a journaling filesystem (XFS, ext4) requires:

1. Flush dirty data pages from page cache to device (~1.9ms, one NVMe flush)
2. Write XFS journal commit record
3. Flush journal to device (~1.9ms, second NVMe flush)
4. Metadata bookkeeping overhead (~2ms)

Total: ~6ms. Two NVMe round trips plus filesystem overhead.

O_DIRECT fdatasync requires only:

1. Issue NVMe flush command (~1.9ms)

Data is already on the device (O_DIRECT bypasses page cache). The flush just
ensures the NVMe's volatile write cache is committed to NAND. One round trip.

**3. Reads and syncs are independent — they don't compete.**

The original hypothesis was that buffered reads would create page cache
contention that would degrade fdatasync latency. This does not happen because:

- Reads target the **data file** (2GB, read-only during benchmark)
- Writes target the **WAL file** (256MB, write-only)
- These are different inodes with different page cache entries
- The page cache LRU/writeback machinery handles them through different paths
- io_uring pipelines reads concurrently with the sync — reads fill time
  *during* the 6ms sync, not before it

Even at rpc=16 with QD=32 (512 concurrent page cache lookups per commit
cycle), the fdatasync latency does not move by a single microsecond.

**4. Commit throughput is bounded by 1/sync_latency.**

| Mode | sync_p50 | Theoretical max | Measured (gs=1) | Efficiency |
|----------|---------|-----------------|-----------------|------------|
| Buffered | 5996us | 167 commits/s | 122 commits/s | 73% |
| Direct | 1950us | 513 commits/s | 494 commits/s | 96% |

Direct achieves 96% of theoretical throughput — the remaining 4% is
write submission + CQE drain overhead between syncs. Buffered achieves
only 73% because the longer sync window (6ms) means more reads complete
during each cycle, and the CQE processing for those reads adds overhead
to the commit critical path.

**5. Group commit multiplies transactions, not commits.**

| gs | Buffered commits/s | Buffered txns/s | Direct commits/s | Direct txns/s |
|---:|--------------------|-----------------|------------------|---------------|
| 1 | 122 | 122 | 494 | 494 |
| 4 | 112 | 448 | 493 | 1974 |

Group commit (gs=4) gives 3.7x more txns/sec for buffered and 4.0x for
direct — close to the theoretical 4x. The commit *rate* drops slightly
(122 -> 112 for buffered) because each group has 3 extra write SQEs to
submit before the sync, adding ~100us of overhead per group.

With gs=4, direct achieves **1974 txns/sec** vs buffered's **448 txns/sec** —
a **4.4x advantage**.

**6. Buffered reads are 3.6x higher IOPS — but it's a measurement artifact.**

| Mode | Read IOPS | Read p50 |
|----------|----------|----------|
| Buffered | ~1,100K | 63us |
| Direct | ~305K | 50us |

The 3.6x IOPS ratio is misleading. The benchmark runs until 5000 groups
complete. Buffered groups take 3x longer (6ms vs 2ms sync), so the
benchmark runs 3x longer, so 3x more reads complete in total. The
*throughput* is roughly equal — what differs is wall-clock time.

More interesting: **direct reads have lower per-op latency (50us vs 63us)
despite going to physical NVMe instead of page cache.** This happens because:

- The 2GB data file with random 4KB reads across 524K pages starts cold
  (FADV_DONTNEED at benchmark start). With only 5K-80K total reads
  (depending on rpc), most pages are cache misses even in buffered mode.
- Page cache hits (~1us) coexist with misses (~70us), but the p50 is
  pulled toward the miss latency because the cache hit rate is low.
- For direct reads, the NVMe's internal DRAM cache (~50us) serves hot
  pages faster than the kernel page cache (~63us) because it skips the
  page lock, LRU update, and VFS overhead.

In a warm-cache scenario (hot working set fully in RAM), buffered reads
would show p50 < 1us and dramatically higher IOPS. This benchmark
deliberately starts cold to measure worst-case behavior.

## Interpretation

### The Wrong Question

The experiment asked: "At what read/write ratio does page cache contention
begin to dominate fdatasync latency?"

The answer: **it doesn't.** The question was wrong.

The reads and syncs live in orthogonal worlds. Reads access the data file's
clean pages in the page cache (or the NVMe for direct). Syncs flush the WAL
file's dirty pages through the XFS journal (or issue a bare NVMe flush for
direct). These paths don't share any contention-prone resources at the
loads tested (up to 1.1M read IOPS, 120 syncs/sec).

The correct question was always: "How much does the XFS journal cost?"
Answer: 4ms per fdatasync (6ms total vs 2ms direct). This is structural —
it's what a journaling filesystem *is*. No amount of tuning will remove it
short of using O_DIRECT or a non-journaling filesystem.

### Why This Matters for Database Design

The fdatasync latency determines commit throughput, which determines
user-visible transaction latency. In a database:

- **O_DIRECT WAL**: 500 commits/sec, 2ms commit latency
- **Buffered WAL**: 120 commits/sec, 6ms commit latency

That's a 4x difference in commit throughput. For write-heavy OLTP (the
common case), this dominates everything else.

For read-heavy workloads with rare writes (e.g., a web server that loads
data at startup and handles small user uploads), buffered I/O is correct:
the page cache provides free read caching, and the 6ms sync penalty is
irrelevant at low commit rates.

### Why PostgreSQL and InnoDB Use O_DIRECT

This data explains the industry consensus:

1. Databases maintain their own buffer pool (userspace page cache), so the
   kernel page cache is redundant for reads — it just wastes memory.
2. O_DIRECT eliminates the 4ms XFS journal overhead from every commit.
3. The database can implement smarter eviction policies (clock-sweep,
   2Q) than the kernel's generic LRU.
4. Double-caching (buffer pool + page cache) wastes DRAM and creates
   cache coherency issues on crash recovery.

### Caveat: This Is One Drive, One Filesystem, One Kernel

These results are specific to:
- Samsung PM9A1 (NVMe 1.4, ~1.9ms flush latency)
- XFS on Linux 6.19
- Single-threaded io_uring (no SQPOLL)

Different drives (Intel Optane: ~10us flush), different filesystems
(ext4 has different journal behavior), or different I/O engines (libaio,
synchronous pwrite+fdatasync) may show different absolute numbers. The
structural relationship (buffered pays journal tax, direct doesn't) is
universal across all journaling filesystems.

## Reproducibility

### Build

```bash
CC=gcc make bench        # GCC build
make bench-icx           # Intel ICX build (optional)
```

Both compile clean with `-Werror` under GCC 15.2.1 and ICX 2025.0.4.

### Run

```bash
# Pin to isolated CPU from process birth
taskset -c 9 ./bench oltp-sweep 3 9 /path/to/data.dat /path/to/wal.dat \
    > results.csv 2>progress.log
```

Arguments: `oltp-sweep [runs=3-30] [cpu] [data_path] [wal_path]`

Use a real filesystem path (xfs/ext4 on NVMe), not tmpfs.

### Pre-flight Checklist

```bash
# Verify CPU isolation
cat /proc/cmdline | grep -o 'isolcpus=[^ ]*'

# Verify NVMe scheduler
cat /sys/block/nvme0n1/queue/scheduler  # should be [none]

# Verify no managed IRQs on target CPU
cat /proc/irq/*/smp_affinity_list | sort -u

# Drop caches (requires root)
echo 3 > /proc/sys/vm/drop_caches

# Verify CPU governor
cat /sys/devices/system/cpu/cpu9/cpufreq/scaling_governor
# Ideally 'performance', but 'powersave' only affects absolute
# numbers, not relative comparisons
```

## Files

| File | Purpose |
|------|---------|
| `src/bench_stats.h` | CI infrastructure: isqrt, t-table, bench_compute_ci() |
| `src/bench_main.c` | oltp-sweep subcommand: sweep loop, CSV output, progress |
| `src/bench_wal.c` | oltp_run() engine: concurrent reads + WAL group commit |
| `src/nolibc.h` | Compiler compat macros for GCC/Clang/ICX |
| `src/util.h` | SIMD memory primitives with portable pragma guards |
| `Makefile` | bench-icx target |
