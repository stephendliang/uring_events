# uring_server

Single-threaded, io_uring-native HTTP server. Freestanding build — no glibc, no liburing, raw syscalls only. 26KB static binary. Returns a static "OK" response; this is a benchmark harness / framework skeleton.

**No epoll. No thread pools. No locks. No libc.**

## File Map

| File | Purpose | Lines |
|------|---------|-------|
| `src/main.c` | Entry point, arg parsing, calls `server_run()` | 39 |
| `src/event.c` | Event loop, connection handlers, SQE templates, server init | 714 |
| `src/event.h` | Public API: `server_run(port, cpu)` | 5 |
| `src/uring.h` | io_uring ring structs, inline hot-path ops (get_sqe, submit, buf recycle) | 391 |
| `src/uring.c` | Cold-path io_uring init: mmap, ring setup, buffer ring manager | 307 |
| `src/nolibc.h` | Freestanding libc: raw syscalls, `_start`, `memset`/`memcpy`, `_fmt_write` | 338 |
| `src/util.h` | SIMD memory primitives: 3-tier dispatch (AVX-512/AVX2/scalar) | 273 |
| `src/core.h` | Type aliases, logging macros, `likely`/`unlikely`/`prefetch_r` | 23 |
| `src/sqe_avx512.h` | `PREP_SQE`: single `_mm512_store_si512` for 64-byte SQE copy | 10 |
| `src/sqe_avx2.h` | `PREP_SQE`: two `_mm256_store_si256` for 64-byte SQE copy | 12 |
| `src/sqe_scalar.h` | `PREP_SQE`: struct copy + field patches | 7 |

```
main.c → event.h → event.c → uring.h (inline hot path)
                               ↓
                             uring.c (cold init)
         event.c → sqe_{avx512,avx2,scalar}.h (compile-time select)
         All    → core.h → nolibc.h
                → util.h (SIMD memory ops)
```

## Build

```bash
make release    # -O3 -march=native -ffreestanding -nostdlib -static → ./event (26KB)
make debug      # -O0 -g -DDEBUG (enables LOG_INFO/WARN/ERROR/BUG)
make clean
```

Key compiler flags: `-ffreestanding -nostdlib -nostartfiles -static -fno-stack-protector`. The `_MM_MALLOC_H_INCLUDED` guard prevents `immintrin.h` from pulling in `mm_malloc.h` (which needs `stdlib.h`). LTO + `-ffunction-sections -fdata-sections -Wl,--gc-sections` in release.

## Architecture

### io_uring Setup Flags

| Flag | Rationale |
|------|-----------|
| `IORING_SETUP_SUBMIT_ALL` | All-or-nothing submission; prevents partial SQE commits |
| `IORING_SETUP_SINGLE_ISSUER` | Kernel skips submission locking (single-threaded) |
| `IORING_SETUP_DEFER_TASKRUN` | Completions batch in kernel; run only on `submit_and_wait` |
| `IORING_SETUP_COOP_TASKRUN` | No async TWA interrupts; we control task_work |
| `IORING_SETUP_CQSIZE` | CQ sized to 4x SQ depth; prevents overflow under burst |
| `IORING_SETUP_NO_SQARRAY` | Identity-mapped SQ; skip kernel array indirection (6.6+, fallback if missing) |

**SQPOLL is explicitly avoided.** Kernel polling threads burn CPU and fight for cache with userspace.

### Event Loop

Single-syscall submit/wait via `uring_submit_and_wait()` → `sys_io_uring_enter()`. CQ drain is direct ring access with acquire/release barriers:

```c
u32 tail = smp_load_acquire(cq->ktail);
while (head != tail) {
    struct io_uring_cqe *cqe = &cqes[head & cq_mask];
    // dispatch on decode_op(cqe->user_data)
    head++;
}
smp_store_release(cq->khead, head);
```

### User_data Encoding

Every CQE carries the operation context in 64 bits — no lookup table:

```
[fd:32 | op:8 | buf_idx:16 | unused:8]
```

`decode_fd()`, `decode_op()`, `decode_buf_idx()` are shift/mask macros. Op types: `OP_ACCEPT`, `OP_RECV`, `OP_SEND`, `OP_CLOSE`, `OP_SETSOCKOPT`, `OP_SEND_ZC`.

### Multishot Accept + Recv

- **Accept**: `IORING_OP_ACCEPT` + `IORING_ACCEPT_MULTISHOT` + `IORING_FILE_INDEX_ALLOC`. Single SQE generates CQEs until `IORING_CQE_F_MORE` is absent (then rearm). Accepted fds go directly into the fixed file table (direct descriptors — no `accept4` fd).
- **Recv**: `IORING_OP_RECV` + `IORING_RECV_MULTISHOT` + `IOSQE_BUFFER_SELECT`. Buffer ID from `cqe->flags >> IORING_CQE_BUFFER_SHIFT`. Recv buffers come from provided buffer ring (group 0).

### Buffer Ring Manager

Unified mmap for multiple buffer groups (`struct buf_ring_mgr`). Layout per group: `io_uring_buf` ring + data buffers + optional ZC bitmap. Huge pages attempted, fallback to regular pages.

- **Group 0** — recv buffers: 4096 x 2KB, pre-filled ring, recycled on send completion.
- **Group 1** — ZC send buffers: 1024 x 4KB, bitmap-tracked allocation.
- `buf_ring_recycle()` / `buf_ring_sync()` — hot-path inline, batched barrier.
- `buf_ring_zc_alloc()` — O(1) via hierarchical bitmap summary (`free_summary` + `__builtin_ctz`).

### Zero-Copy Send (kernel 6.10+)

Probed at startup via `IORING_REGISTER_PROBE`. If `IORING_OP_SEND_ZC` is supported, ZC group is enabled. Response data is copied into a ZC buffer, pushed to kernel ring, sent with `IORING_OP_SEND_ZC` + `IORING_RECVSEND_BUNDLE`. Buffer recycled on `IORING_CQE_F_NOTIF` (NIC DMA complete), not on send completion. Falls back to regular `IORING_OP_SEND` if unavailable.

### PREP_SQE: SIMD Template Copy

SQE templates are 64-byte aligned `const struct io_uring_sqe` with pre-filled opcodes/flags. `PREP_SQE(sqe, template, fd, user_data)` copies + patches in one step:

- **AVX-512**: single `_mm512_store_si512` (1 instruction, 64 bytes)
- **AVX2**: two `_mm256_store_si256` with `_mm256_blend_epi32` for fd/user_data
- **Scalar**: struct copy + field assignment

Selected at compile time via `#if defined(__AVX512F__)` / `__AVX2__`.

### No Syscalls in Hot Path

After `io_uring_setup`, every I/O operation goes through the ring:

- **TCP_NODELAY**: `IORING_OP_URING_CMD` + `SOCKET_URING_OP_SETSOCKOPT` (kernel 6.7+)
- **Connection close**: `IORING_OP_CLOSE`, never `close(2)`
- **Accept**: multishot direct, no `accept4(2)`

The only syscall per loop iteration is `io_uring_enter`.

### Hot Path vs Cold Path Split

`uring.h` — inline functions used every loop iteration: `uring_get_sqe()`, `uring_submit()`, `uring_submit_and_wait()`, `buf_ring_recycle()`, `buf_ring_sync()`, ZC bitmap ops.

`uring.c` — called once at startup: `uring_init()`, `uring_mmap()`, `buf_ring_mgr_init()`, `uring_register_fixed_files()`, `buf_ring_zc_probe()`. Reduces icache pressure in the hot loop.

## Freestanding Build

`nolibc.h` replaces glibc entirely:

- `_start` entry point (naked, sets up argc/argv, calls `main`, `exit_group`)
- Raw `syscall` instruction via `_syscall6()` primitive
- Macro aliases: `close()`, `mmap()`, `socket()`, `bind()`, etc. → `sys_*()` wrappers
- `memset`/`memcpy` with `__attribute__((externally_visible))` — GCC emits implicit calls for large aggregate init
- `_fmt_write()` — minimal `printf` to stderr (256-byte stack buffer, handles `%s %d %u %x %zu %p`)
- Signal handling: `k_sigaction()` with raw `rt_sigaction` + `SA_RESTORER` trampoline
- `#pragma GCC optimize("no-tree-loop-distribute-patterns")` prevents GCC from converting loops back to memset/memcpy calls

## SIMD Memory Primitives (util.h)

3-tier dispatch at compile time:

| Tier | Detection | Ops |
|------|-----------|-----|
| AVX-512 | `__AVX512F__` | 64B stores: `_mm512_store`, `_mm512_stream`, `mem_iota_u32` (16-wide) |
| AVX2 | `__AVX2__` | 2x 32B stores per cache line |
| Scalar | fallback | 8B `u64` stores in loop |

All provide: `mem_zero_aligned`, `mem_zero_nt`, `mem_fill_nt`, `mem_copy_aligned`, `mem_copy_nt`, `mem_zero_cacheline`, `mem_iota_u32`. Non-temporal (NT) variants bypass cache for kernel-bound buffers.

## Key Constants (event.c)

| Constant | Value | Notes |
|----------|-------|-------|
| `SQ_ENTRIES` | 2048 | SQE ring depth |
| `CQ_ENTRIES` | 8192 | 4x SQ, prevents overflow |
| `NUM_BUFFERS` | 4096 | Recv provided buffers (power of 2) |
| `BUFFER_SIZE` | 2048 | Per recv buffer |
| `MAX_CONNECTIONS` | 65536 | Fixed file table size, conn_state array size |
| `LISTEN_BACKLOG` | 4096 | TCP listen backlog |
| `ZC_NUM_BUFFERS` | 1024 | Zero-copy send buffers |
| `ZC_BUFFER_SIZE` | 4096 | Per ZC buffer |

## Bitfield-Packed Structures

- `struct conn_state` — 1 byte: `closing:1`, `recv_active:1`, `reserved:6`. Array of 65536 = 64KB.
- `struct buf_ring_group` — 32 bytes (half cache line). `bgid` derived from array index, `num_buffers` from `mask + 1`, `is_zc` from `free_bitmap != NULL`.
- `struct buf_ring_mgr` — 88 bytes. Bitfield metadata: `num_groups:2`, `initialized:1`.
- Layout verified at compile time via `_Static_assert`.

## Constraints

- **Linux 6.7+** required (socket commands via `IORING_OP_URING_CMD`). Missing features are fatal.
- **x86-64 only** — raw syscall ABI, SIMD intrinsics.
- **Single-threaded** — one process, one core (multi-core is future work).
- **No TLS** — no crypto, no MSG_MORE, no TLS record bundling.
- **No rate limiting** — no per-client tracking, no 429 responses.
- **No dynamic content** — static "OK" response only.
- **Not a framework** — application logic compiled in.

## Performance

See [docs/2026-01-30-bench.md](docs/2026-01-30-bench.md) for full results.

| Metric | Value | Conditions |
|--------|-------|------------|
| Requests/sec | 104,753 | 100 connections, 2-core VPS |
| Requests/sec | 113,801 | 500 connections, 2-core VPS |
| vs nginx 1.28.1 | +42% throughput | 100 connections |
| Avg latency | 0.89ms | 100 connections |
| p99 latency | 2.99ms | 100 connections |
| Binary size | 26KB | Release build, stripped by LTO/gc-sections |
| Syscalls/request | ~0 | Multishot amortized |
| Locks in hot path | 0 | Single-threaded, no shared state |
