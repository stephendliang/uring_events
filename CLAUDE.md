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
| `src/sqe.h` | `PREP_SQE` / `PREP_SQE_FILE` — compile-time SIMD dispatch (AVX-512/AVX2/scalar) |
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
            event.c ─→ sqe.h (SIMD compile-time select)
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

## Key Internals

User_data encoding (64-bit, no lookup table): `[fd:32 | op:8 | buf_idx:16 | unused:8]`. Op codes in `enum op_type` at top of `event.c`. Pre-shifted constants (`OP_*_SHIFTED`) avoid per-SQE shifts.

For architecture details see `docs/server.md`. For bench suite see `docs/bench.md`.

## Constraints

- **Linux 6.7+** required (`IORING_OP_URING_CMD` for async setsockopt). Missing features are fatal.
- **x86-64 only** — raw syscall ABI, SIMD intrinsics, RDTSC.
- **Intel CPUs** — TSC frequency via CPUID 0x15/0x16. No AMD fallback.
- **No TLS, no rate limiting, no dynamic content, not a framework.**

## Docs

`docs/server.md` — server architecture, `docs/bench.md` — bench suite, `docs/benchmarks.md` — benchmark history, `docs/multicore.md` — multicore design, `docs/zerocopy.md` — ZC send analysis, `docs/oltp-sweep.md` — fdatasync analysis, `docs/roadmap.md` — planned work

## Plans

Future proposals in `plans/`;
