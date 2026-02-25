# uring_server

io_uring-native HTTP server. Freestanding build — no glibc, no liburing, raw syscalls only. ~30KB static-PIE binary. Static "OK" response; benchmark harness / framework skeleton.

Single-threaded or multicore (`#ifdef MULTICORE`) via raw `clone()` — shared-nothing, one io_uring per worker, zero cross-thread communication. **No epoll. No thread pools. No locks. No libc.**

## File Map

| File | Purpose |
|------|---------|
| `src/main.c` | Entry point, arg parsing, dispatches `server_run()` or `server_start()` |
| `src/event.c` | Event loop, connection handlers, SQE templates, idle sweep, cancel-on-close, multicore spawn |
| `src/event.h` | Public API: `server_run(port, cpu)`, `server_start(port, cpu_start, num_workers)` |
| `src/uring.h` | io_uring ring structs, inline hot-path ops (get_sqe, submit, buf recycle) |
| `src/uring.c` | Cold-path io_uring init: mmap, ring setup, buffer ring manager |
| `src/nolibc.h` | Freestanding libc: raw syscalls, `_start` with PIE relocation, thread primitives |
| `src/util.h` | SIMD memory primitives: 3-tier dispatch (AVX-512/AVX2/scalar) |
| `src/core.h` | Type aliases, logging macros, `likely`/`unlikely`/`prefetch_r` |
| `src/sqe_avx512.h` | `PREP_SQE` via single `_mm512_store_si512` + masked set |
| `src/sqe_avx2.h` | `PREP_SQE` via two `_mm256_store_si256` + blend |
| `src/sqe_scalar.h` | `PREP_SQE` via struct copy + field patches |
| `src/bench_main.c` | Bench entry point, CLI parsing, 7 modes, result formatting |
| `src/bench.c` | Disk I/O engine: slot-based I/O loop, file setup, stats |
| `src/bench_wal.c` | WAL group commit (`wal_run`) and OLTP mixed (`oltp_run`) |
| `src/bench_conn.c` | Standalone idle-tracking microbenchmark (sieve/linear/wheel) |
| `src/bench.h` | Bench config/result structs, enums (io_mode, access_pattern, io_direction) |
| `src/bench_wal.h` | WAL/OLTP config/result structs, WAL user_data encoding |
| `src/bench_sqe.h` | Scalar SQE prep for bench (BENCH_ENCODE_UD, read/write/fsync) |
| `src/bench_stats.h` | Timing (clock_gettime), shell sort, percentiles, CI computation |
| `src/bench_syscalls.h` | File I/O syscalls (openat, fallocate, fadvise64, getrandom, ...) |

```
main.c  ─→ event.h ─→ event.c ─→ uring.h (inline hot path)
                                     ↓
                                   uring.c (cold init)
            event.c ─→ sqe_{avx512,avx2,scalar}.h (compile-time select)
            All     ─→ core.h ─→ nolibc.h
                    ─→ util.h (SIMD memory ops)
            uring.h ─→ core.h, util.h
```

**Gotcha**: `event.c` defines configuration constants (`SQ_ENTRIES`, `NUM_BUFFERS`, etc.) *before* `#include "uring.h"`, so `uring.h` sees those values.

## Build

```bash
make release            # -O3 -march=native → ./event (~30KB)
make debug              # -O0 -g -DDEBUG (enables LOG_INFO/WARN/ERROR/BUG)
make release-multicore  # -DMULTICORE → shared-nothing multi-worker
make debug-multicore    # multicore + debug logging
make release-file-io    # -DFILE_IO → file read/write/fdatasync ops
make bench              # -O3 -march=native → ./bench (disk I/O benchmark)
make bench-debug        # -O0 -g -DDEBUG → ./bench-debug
make bench-icx          # Intel ICX compiler → ./bench-icx
make bench-conn         # standalone idle-tracking microbenchmark → ./bench-conn
make clean
```

Compiler flags: `-ffreestanding -nostdlib -nostartfiles -static-pie -fPIE -fno-stack-protector`. `_MM_MALLOC_H_INCLUDED` guard prevents `immintrin.h` pulling in `mm_malloc.h`. LTO + gc-sections in release.

```bash
./event 8080 4        # single worker on CPU 4
./event 8080 4 4      # 4 workers on CPUs 4, 6, 8, 10 (multicore build)
```

## Architecture

### io_uring Setup (`uring_init` in uring.c)

Flags: `SUBMIT_ALL`, `SINGLE_ISSUER`, `DEFER_TASKRUN`, `CQSIZE` (4x SQ), `NO_SQARRAY` (6.6+, fallback if missing). SQPOLL explicitly avoided — kernel polling threads burn CPU and fight for cache.

### Event Loop (`event_loop` in event.c)

Single `io_uring_enter` per iteration (submit + wait). CQ drain via direct ring access with acquire/release barriers. Key properties:
- 1 syscall per iteration
- 0 userspace allocations in hot path — all buffers pre-allocated at startup
- Batched buffer recycling — single store-release after entire CQ drain
- CQE prefetching hides memory latency
- CQ overflow is fatal (silent completion loss)

### User_data Encoding

64-bit, no lookup table: `[fd:32 | op:8 | buf_idx:16 | unused:8]`. Op codes in `enum op_type` at top of `event.c`. Pre-shifted constants (`OP_*_SHIFTED`) avoid per-SQE shifts.

### Connection Lifecycle

```
accept → init conn_state, idle_touch, queue setsockopt(TCP_NODELAY), queue multishot recv
recv   → idle_touch, queue send (or send_zc) with buf_idx
send   → recycle recv buffer inline; close on error/partial
close  → cancel active recv first (cancel-on-close), then queue IORING_OP_CLOSE
timeout→ sweep idle LRU from oldest, close expired
```

Four guard bits in `struct conn_state` (1 byte per fd, see `event.c`): `recv_active` prevents duplicate multishot recv; `closing` blocks new ops; `cancel_sent` prevents double-cancel; `in_idle` tracks LRU membership. If `IORING_CQE_F_MORE` is absent, multishot was terminated and must be re-armed.

### Cancel-on-Close (`queue_close` in event.c)

Before closing, cancel active multishot recv via `IORING_OP_ASYNC_CANCEL` to prevent orphaned CQEs after fd slot reuse. Close deferred until cancel CQE. SQ-full fallback reinserts into idle LRU for retry.

### Idle Sweep (`sweep_idle_connections` in event.c)

RDTSC-based, O(1) LRU tracking. Multishot timeout fires every 5s. Intrusive doubly-linked list (sentinel at index 0) sorted by activity time. Sweep walks from oldest, stops at first non-expired node — O(k) where k = expired.

TSC frequency from CPUID 0x15/0x16 at startup. Hard-fails if unavailable (Intel-specific).

**Planned**: timing wheel replacing LRU. See `docs/roadmap.md` §2, benchmarked in `src/bench_conn.c`.

### Buffer Ring Manager (`buf_ring_mgr` in uring.h/uring.c)

Unified mmap for multiple buffer groups. Group 0: 4096x2KB recv buffers (provided ring, recycled on send). Group 1: ZC send (unused — ZC sends from static response buffer directly). Huge pages attempted, fallback to regular. Hot path uses cached pointers in `struct buf_ring`, synced once per CQ drain batch.

### Zero-Copy Send

Runtime-probed via `IORING_REGISTER_PROBE`. Two CQEs per send (completion + NOTIF). `zc_inflight` cap at 256 prevents kernel ENOMEM; overflow falls back to regular send. Net loss for 88-byte responses — see `docs/zerocopy.md`.

### SQE Templates (sqe_*.h)

64-byte aligned `const` templates with pre-filled opcodes/flags. `PREP_SQE(sqe, template, fd, user_data)` does SIMD copy + patch in one step. Only `fd` and `user_data` vary per-SQE. Exception: `prep_setsockopt_direct` uses scalar because `IORING_OP_URING_CMD` has a 16-byte cmd area at offset 48.

### Multicore (`server_start` in event.c, `#ifdef MULTICORE`)

N workers via raw `clone()` syscall 56 (asm trampoline in `nolibc.h`). Each worker owns: listen socket (`SO_REUSEPORT`), io_uring, fixed file table, buffer rings, 832KB `worker_data` (mmap'd). `CLONE_VM | CLONE_THREAD | CLONE_SIGHAND` but no `CLONE_FILES`. CPU stride-2 skips HT siblings. Futex-based join. Shared `g_shutdown` flag for cooperative exit. See `docs/multicore.md`.

### Freestanding Build (nolibc.h)

`_start` does static-PIE self-relocation (walk `_DYNAMIC`, apply `R_X86_64_RELATIVE`). `_syscall6()` primitive wraps x86-64 syscall ABI. Macro aliases (`close`, `mmap`, `socket`, etc.) map to `sys_*()` wrappers. `memset`/`memcpy` provided with `externally_visible` for GCC implicit calls. `#pragma GCC optimize("no-tree-loop-distribute-patterns")` prevents GCC converting loops back to memset/memcpy.

## Constraints

- **Linux 6.7+** required (`IORING_OP_URING_CMD` for async setsockopt). Missing features are fatal.
- **x86-64 only** — raw syscall ABI, SIMD intrinsics, RDTSC.
- **Intel CPUs** — TSC frequency via CPUID 0x15/0x16. No AMD fallback.
- **No TLS, no rate limiting, no dynamic content, not a framework.**

## Docs

| File | Content |
|------|---------|
| `docs/server.md` | Deep server architecture reference (io_uring setup, event loop, etc.) |
| `docs/bench.md` | Bench suite architecture (build, usage, 7 CLI modes, internals) |
| `docs/benchmarks.md` | Benchmark history: VPS, workstation (isolcpus), nginx comparison |
| `docs/multicore.md` | Multicore design + localhost/LAN benchmarks |
| `docs/zerocopy.md` | Why SEND_ZC is a net loss for small responses |
| `docs/oltp-sweep.md` | Buffered vs O_DIRECT fdatasync analysis (FILE_IO bench) |
| `docs/roadmap.md` | Reactor feature status and planned work |

## Performance

See `docs/multicore.md` and `docs/benchmarks.md`. Headlines: 567K req/s single-thread, 913K 4-worker (localhost, wrk-bottlenecked). Single thread saturates 1GbE (246K req/s).
