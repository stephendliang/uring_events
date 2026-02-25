# Benchmark Results: io_uring HTTP Server

Tested on 2-core VPS (specific CPU model, kernel version, and memory not recorded — results are directional, not reproducible to exact numbers).

## Test Configuration

- **Tool**: wrk 4.2.0
- **Threads**: 2 (wrk pinned to non-server core not enforced)
- **Duration**: 20 seconds
- **Response**: "OK" (2 bytes, ~90 bytes with headers)

---

## 2026-02-20 — Dedicated workstation (isolcpus)

20-core workstation, kernel 6.19.2-2-cachyos, `isolcpus=managed_irq,domain:4-11`.
Server on isolated CPU 6, wrk -t1 on CPU 0. GCC release build.

### Pinned (server CPU 6, wrk CPU 0)

| Metric | 100c | 500c |
|--------|------|------|
| **Req/sec** | 368,149 | 387,889 |
| **Latency avg** | 137us | 644us |
| **Latency p50** | 132us | 637us |
| **Latency p90** | 148us | 790us |
| **Latency p99** | 274us | 1.16ms |
| **Transfer/sec** | 31.60MB | 33.29MB |

### Unpinned wrk (server CPU 0, wrk free to migrate)

| Metric | 100c | 500c |
|--------|------|------|
| **Req/sec** | 362,387 | 364,590 |
| **Latency avg** | 143us | 688us |
| **Latency p50** | 135us | 667us |
| **Latency p90** | 161us | 821us |
| **Latency p99** | 410us | 1.19ms |
| **Transfer/sec** | 31.10MB | 31.29MB |

### Both isolated (server CPU 6, wrk CPU 8)

| Metric | 100c | 500c |
|--------|------|------|
| **Req/sec** | 359,198 | 358,961 |
| **Req/sec stdev** | 9.86K | 9.97K |
| **Latency avg** | 141us | 697us |
| **Latency p50** | 140us | 692us |
| **Latency p90** | 150us | 834us |
| **Latency p99** | 168us | 0.96ms |
| **Transfer/sec** | 30.83MB | 30.81MB |

### Isolation effect

| Config | 100c req/s | 100c stdev | 100c p99 | 500c req/s | 500c stdev | 500c p99 |
|--------|-----------|-----------|---------|-----------|-----------|---------|
| wrk free | 362,387 | — | 410us | 364,590 | — | 1.19ms |
| server isolated | 368,149 | 37.5K | 274us | 387,889 | 31.9K | 1.16ms |
| both isolated | 359,198 | 9.86K | 168us | 358,961 | 9.97K | 0.96ms |

Throughput is ~5% lower with both sides isolated (expected — isolated cores
don't receive softirq/networking work from the scheduler), but variance
collapses by 4-5x and p99 drops dramatically (410→168us at 100c, 1.19→0.96ms
at 500c). Full isolation trades peak throughput for deterministic latency.

---

## 2026-02-08 — Unified nolibc build

After eliminating all `#ifdef NOLIBC` conditionals (unified freestanding build).
Same 2-core VPS, same test parameters.

### 100 Connections

| Metric | Jan 30 (non-ZC) | Feb 8 (unified) | Delta |
|--------|-----------------|-----------------|-------|
| **Req/sec** | 73,570 | 104,753 | **+42.4%** |
| **Latency avg** | 1.30ms | 0.89ms | **-31.5%** |
| **Latency p50** | 1.31ms | 0.73ms | **-44.3%** |
| **Latency p99** | 3.38ms | 2.99ms | **-11.5%** |
| **Transfer/sec** | 6.31MB | 8.99MB | +42.5% |

### 500 Connections

| Metric | Jan 30 (non-ZC) | Feb 8 (unified) | Delta |
|--------|-----------------|-----------------|-------|
| **Req/sec** | 98,188 | 113,801 | **+15.9%** |
| **Latency avg** | 4.43ms | 3.48ms | **-21.4%** |
| **Latency p50** | 4.28ms | 3.41ms | **-20.3%** |
| **Latency p99** | 8.73ms | 8.18ms | **-6.3%** |
| **Transfer/sec** | 8.43MB | 9.77MB | +15.9% |

### Notes

Gains are cumulative from all commits since Jan 30 (buffer ring manager,
bitfield packing, cold-path split into uring.c, unified nolibc build),
not solely from the nolibc unification. Different VPS instance/kernel
version may also contribute.

---

## 2026-01-30 — Initial benchmark

### 100 Connections

| Metric | nginx 1.28.1 | io_uring (non-ZC) | io_uring (ZC) |
|--------|--------------|-------------------|---------------|
| **Req/sec** | 57,238 | 73,570 | 74,102 |
| **Latency avg** | 1.69ms | 1.30ms | 1.29ms |
| **Latency p50** | 1.85ms | 1.31ms | 1.30ms |
| **Latency p99** | 3.75ms | 3.38ms | 3.38ms |
| **Transfer/sec** | 8.13MB | 6.31MB | 6.36MB |

### 500 Connections

| Metric | nginx 1.28.1 | io_uring (non-ZC) | io_uring (ZC) |
|--------|--------------|-------------------|---------------|
| **Req/sec** | 73,738 | 98,188 | 100,541 |
| **Latency avg** | 6.34ms | 4.43ms | 4.31ms |
| **Latency p50** | 6.07ms | 4.28ms | 4.11ms |
| **Latency p99** | 11.68ms | 8.73ms | 8.46ms |
| **Transfer/sec** | 10.48MB | 8.43MB | 8.63MB |

### Analysis

#### io_uring vs nginx

| Connections | Throughput Gain | Latency Reduction |
|-------------|-----------------|-------------------|
| 100 | +29.5% | -23.7% avg, -9.9% p99 |
| 500 | +36.4% | -32.0% avg, -27.6% p99 |

Note: nginx shows higher Transfer/sec despite lower Req/sec because its response includes more headers (Server, Date, Content-Type, etc.), so each response is larger in bytes.

#### Zero-Copy vs Non-ZC

| Connections | Throughput Gain | Latency Reduction |
|-------------|-----------------|-------------------|
| 100 | +0.7% | -0.8% avg |
| 500 | +2.4% | -2.7% avg, -3.1% p99 |

---

## Conclusions

1. **io_uring dominates nginx** by 30-36% in throughput and 24-32% in latency
2. **Cumulative optimizations** (Jan 30 to Feb 8) yielded +42% at 100c, +16% at 500c
3. **Zero-copy provides marginal benefit** (~2%) for tiny responses
4. **ZC advantage grows with load** - more visible at 500 connections
5. **ZC would shine with larger payloads** where kernel buffer copy cost matters

## Why io_uring Wins

- Single-threaded event loop (no process/thread overhead)
- Batched syscalls (multiple I/O ops per enter/exit)
- Multishot accept/recv (arm once, fire many)
- Provided buffer ring (zero userspace-kernel copies for recv)
- DEFER_TASKRUN (process completions in userspace context)

## Test Commands

```bash
# Build
make clean && make release

# Run server (pinned to CPU 0)
./event 8080 0 &

# Benchmark
wrk -t2 -c100 -d20s --latency http://127.0.0.1:8080/
wrk -t2 -c500 -d20s --latency http://127.0.0.1:8080/
```
