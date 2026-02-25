# Server Architecture

Deep reference for the io_uring HTTP server internals. For the quick summary, see `CLAUDE.md`.

## io_uring Setup

`uring_init()` in `src/uring.c` creates the ring with these flags:

- **`IORING_SETUP_SUBMIT_ALL`** — don't stop submitting if one SQE fails
- **`IORING_SETUP_SINGLE_ISSUER`** — only one thread touches this ring (enables kernel fast path)
- **`IORING_SETUP_DEFER_TASKRUN`** — defer task work to the next `io_uring_enter()` (subsumes `COOP_TASKRUN`)
- **`IORING_SETUP_CQSIZE`** — CQ ring is 4x SQ (8192 entries for 2048 SQ)
- **`IORING_SETUP_NO_SQARRAY`** — eliminates the SQ index array indirection (6.6+)

NO_SQARRAY is tried first; if the kernel returns `-EINVAL`, the params struct is fully reset and setup retries without it. Without NO_SQARRAY, the SQ index array is pre-filled with identity mapping (`array[n] = n` via `mem_iota_u32`) to enable O(1) submit.

SQPOLL is deliberately avoided. Kernel polling threads burn a full core, fight for cache, and provide no benefit for a single-issuer design that already does one syscall per iteration.

After setup, `uring_init` attempts **ring fd registration** (`IORING_REGISTER_RING_FDS`, kernel 6.4+). This stores the ring fd in a kernel-side table so `io_uring_enter()` skips the fd-to-file lookup (~40-60 cycles saved per syscall). If registration fails, the raw ring fd is used.

Ring sizing: SQ=2048, CQ=8192 (defined in `event.c`). The CQ 4x multiplier accommodates multishot ops that generate multiple CQEs per SQE (accept, recv, timeout).

## Event Loop

`event_loop()` in `src/event.c` is the core. One `io_uring_enter` call per iteration handles both submission and wait.

```
while (running && !g_shutdown):
    uring_submit_and_wait(ring, 1, 1ms_timeout)
    tail = load_acquire(cq->ktail)

    for each CQE from head to tail:
        prefetch next CQE
        decode user_data → fd, op, buf_idx
        dispatch to handler

    sync buffer ring tail (single store-release if any buffers recycled)
    store_release(cq->khead, head)  // advance CQ consumer
    check CQ overflow (fatal if non-zero)
```

Key design decisions:

**Single syscall per iteration.** `uring_submit_and_wait()` combines submit + wait via `IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG`. The 1ms timeout (`__kernel_timespec`) prevents busy-spinning during idle periods while keeping latency low.

**Cached CQ head.** The event loop caches `cq->khead` locally and writes it back once per drain, not per CQE. We're the only CQ consumer (SINGLE_ISSUER), so no race.

**Batched buffer recycling.** The `buf_ring.tail` is cached locally for the entire CQ drain. Buffer recycles during the drain just write to the ring array and bump the local tail. A single `smp_store_release(&br->tail, ...)` at the end publishes all recycled buffers to the kernel at once. This saves one memory barrier per CQE.

**CQE prefetching.** `prefetch_r(&cqes[(head + 1) & cq_mask])` hides memory latency. CQEs are 16 bytes; prefetching the next one while processing the current one keeps the pipeline full.

**CQ overflow is fatal.** If `cq->koverflow` is non-zero, the kernel silently dropped completions. There is no recovery path — the server would have dangling in-flight ops with no CQE to complete them. The loop exits.

**Inline send-path buffer recycle.** For `OP_SEND`, the recv buffer is recycled directly in the CQE loop (writing to `br_ring->bufs[br_tail & br_mask]`) instead of calling `buf_ring_recycle()`. This avoids function call overhead and uses the already-cached local variables.

## User_data Encoding

64-bit packed, no lookup table:

```
[fd:32 | op:8 | buf_idx:16 | unused:8]
 bits 0-31  bits 32-39  bits 40-55  bits 56-63
```

- `decode_fd(ud)` — `(i32)(ud & 0xFFFFFFFF)`
- `decode_op(ud)` — `(u8)(ud >> 32)`
- `decode_buf_idx(ud)` — `(u16)(ud >> 40)`

Op codes are defined in `enum op_type` at the top of `event.c`. Pre-shifted constants (`OP_ACCEPT_SHIFTED`, `OP_RECV_SHIFTED`, etc.) are `(u64)OP_xxx << 32`, avoiding per-SQE shifts when building user_data.

Why no lookup table: the fd *is* the connection index (fixed file table slots 0..65535). No indirection needed. The op type is encoded in-band so a single CQE decode gives both the operation and the connection without any memory access.

## Connection Lifecycle

```
accept → init conn_state (zero all bits)
       → idle_touch (insert into LRU)
       → queue_setsockopt_nodelay (async TCP_NODELAY via IORING_OP_URING_CMD)
       → queue_recv (multishot)

recv   → idle_touch (update LRU position)
       → if ZC enabled and under inflight cap: recycle buffer, queue_send_zc
       → else: queue_send with buf_idx (buffer recycled on send completion)
       → if !MORE: multishot terminated, re-arm recv

send   → recycle recv buffer (inline in CQE loop)
       → on error: close (benign errors like EPIPE/ECONNRESET are not logged)
       → on partial send (res < HTTP_200_LEN): close (no retry)

close  → 3-phase cancel-on-close sequence (see below)

timeout → sweep_idle_connections (LRU walk)
```

**Multishot recv lifetime.** The kernel sets `IORING_CQE_F_MORE` on each CQE if the multishot recv is still armed. When MORE is absent (buffer exhaustion, error, kernel disarm), `recv_active` is cleared and a new multishot recv must be queued. The `recv_active` guard bit prevents queuing duplicate multishot recvs.

**Partial send handling.** The server does not retry partial sends. An 88-byte HTTP 200 response that doesn't fully send indicates a broken connection. The connection is closed.

**Benign vs fatal errors.** `is_benign_err()` classifies EPIPE, ECONNRESET, EBADF, and ECANCELED as benign (peer went away, expected during normal operation). These are not logged even in debug builds. Other errors trigger LOG_ERROR.

## Cancel-on-Close

`queue_close()` in `src/event.c` implements a 3-phase close sequence to prevent orphaned CQEs after fd slot reuse:

**Phase 1: Cancel.** If `recv_active && !cancel_sent`, submit `IORING_OP_ASYNC_CANCEL` targeting the multishot recv's user_data. Set `cancel_sent = 1`. The close is deferred — `handle_cancel` will issue it.

**Phase 2: Handle cancel.** `handle_cancel()` fires when the cancel CQE arrives. All cancel results (0 = cancelled, -ENOENT = not found, -EALREADY = already completing) lead to the same action: submit `IORING_OP_CLOSE`. The recv is guaranteed to stop producing CQEs after the cancel completes.

**Phase 3: Close.** `handle_close()` zeros all `conn_state` bits for the fd, making the slot available for reuse by the next accept.

**SQ-full fallback.** If the SQ is full at any phase:
- Cancel phase: falls through to `force_close` (close without cancel — accepts the orphan CQE risk as better than leaking the fd)
- Close phase (both in `queue_close` and `handle_cancel`): resets `closing`/`cancel_sent`/`recv_active`, calls `idle_insert_expired()` to re-insert the connection at the head of the idle list with timestamp 0. The next sweep tick will retry the close.

## Idle Sweep

`sweep_idle_connections()` in `src/event.c`.

**Timer.** `IORING_OP_TIMEOUT` with `IORING_TIMEOUT_MULTISHOT` fires every 5 seconds (`SWEEP_INTERVAL_SEC`). One SQE submitted at startup, re-fires automatically. If the multishot is disarmed (MORE absent), it's re-queued.

**LRU design.** Intrusive doubly-linked list using `struct idle_node` (4 bytes per fd: `u16 prev, u16 next`). Index 0 is the sentinel (listen socket, never idle-tracked). The list is circular: `sentinel.next` = oldest, `sentinel.prev` = newest.

- `idle_touch(fd)` — O(1): unlink from current position, insert before sentinel (tail). Update `last_activity[fd]` with current `rdtsc()`.
- `idle_remove(fd)` — O(1): unlink from list, clear `in_idle` flag.
- `idle_insert_expired(fd)` — O(1): insert at head (oldest position) with `last_activity = 0`, forcing expiry on next sweep.

**Sweep walk.** Starts at `idle_list[0].next` (oldest) and walks forward. For each node, compares `rdtsc() - last_activity[fd]` against `idle_timeout_ticks`. Stops at the first non-expired node (list is sorted by activity time). Expired connections are closed via `queue_close()`. Walk is O(k) where k = expired count.

**RDTSC calibration.** `detect_tsc_freq()` uses CPUID leaf 0x15 (exact: `crystal_hz * numerator / denominator`) with fallback to leaf 0x16 (base MHz). Both are Intel-specific. If neither works, the server hard-fails. The idle timeout in ticks is precomputed once: `IDLE_TIMEOUT_SEC * tsc_freq` (30s default).

**Planned migration.** Timing wheel replacing LRU. See `docs/roadmap.md` section 2 and benchmarks in `src/bench_conn.c`.

## SQE Templates

`src/sqe_avx512.h`, `src/sqe_avx2.h`, `src/sqe_scalar.h` — compile-time selected via `#if defined(__AVX512F__)`.

Each SQE is 64 bytes (one cache line). Templates are `static const` (or `static` for non-const send templates that need runtime address patching), 64-byte aligned. They contain pre-filled opcodes, flags, ioprio, and other constant fields.

`PREP_SQE(sqe, template, fd, user_data)` copies the template and patches `fd` and `user_data` in one step:

- **AVX-512**: single `_mm512_load_si512` + `_mm512_mask_set1_epi32` (fd at dword 1) + `_mm512_mask_set1_epi64` (user_data at qword 4) + `_mm512_store_si512`. One load, two masked blends, one store.
- **AVX2**: two `_mm256_load_si256` (low/high halves) + `_mm256_blend_epi32` for fd (low half) + `_mm256_blend_epi32` for user_data (high half) + two stores.
- **Scalar**: struct copy + two field writes.

**`PREP_SQE_FILE`** is a 5-field variant (fd, off, addr, len, user_data) for file I/O ops, using additional masked blends.

**Exception: setsockopt.** `prep_setsockopt_direct()` uses scalar prep (`mem_zero_cacheline` + field writes) because `IORING_OP_URING_CMD` has a 16-byte command area at SQE offset 48, which doesn't map cleanly to the SIMD template pattern.

**Send template patching.** `SQE_TEMPLATE_SEND` and `SQE_TEMPLATE_SEND_ZC` are non-const because their `addr` field (pointer to `HTTP_200_RESPONSE`) needs to be set at runtime (`_start` does PIE relocation, so compile-time address isn't available). Patched once in `server_run()` / `server_start()` before any workers spawn.

## Buffer Ring

`struct buf_ring_mgr` in `src/uring.h`, initialized by `buf_ring_mgr_init()` in `src/uring.c`.

**Unified mmap.** A single `mmap` allocates memory for all buffer groups. Huge pages attempted first (`MAP_HUGETLB`), fallback to regular pages with `MAP_POPULATE`. Each group occupies a contiguous region: ring descriptor array followed by data buffers.

**Group 0: recv buffers.** 4096 buffers x 2KB each (8MB data + 64KB ring). Registered as a provided buffer ring with the kernel (`IORING_REGISTER_PBUF_RING`). When multishot recv completes, the kernel fills one of these buffers and returns its index in `CQE_F_BUFFER`. The buffer is recycled to the ring after the response is sent.

**Group 1: ZC send.** 1024 buffers x 4KB, allocated but currently unused — zero-copy sends use the static `HTTP_200_RESPONSE` buffer directly, not the buffer ring.

**Hot-path struct.** The event loop uses `struct buf_ring` (32 bytes) which caches `br`, `buf_base`, `tail`, `mask`, `buffer_size`, `buffer_shift` from the manager. These are set once during `server_setup_and_run()` and never change.

**Batch sync.** Buffer recycling updates the local `tail` without a memory barrier. `buf_ring_sync()` does a single `smp_store_release(&br->tail, ...)` to publish all recycled buffers at once. Called once per CQ drain batch, not per recycle.

**Zero allocations.** All buffers are pre-allocated at startup. No malloc, no mmap in the hot path.

## Zero-Copy Send

**Runtime probe.** `buf_ring_zc_probe()` in `src/uring.c` uses `IORING_REGISTER_PROBE` to check if `IORING_OP_SEND_ZC` is supported. If available, `ctx->zc_grp` is set; otherwise NULL.

**Dual CQE.** Each ZC send produces two CQEs: the completion CQE (with `IORING_CQE_F_MORE` set, indicating a NOTIF is coming) and the NOTIF CQE (with `IORING_CQE_F_NOTIF` set, indicating the kernel is done with the buffer). `handle_send_zc()` distinguishes between them.

**Inflight cap.** `zc_inflight` tracks pending ZC sends awaiting their NOTIF CQE. Capped at `ZC_MAX_INFLIGHT` (256). When at cap, `handle_recv()` falls back to regular send. This prevents kernel `ENOMEM` from too many pinned pages.

**ENOMEM fallback.** If a ZC send fails with `-ENOMEM`, the handler decrements `zc_inflight` (no NOTIF coming) and falls back to a regular `IORING_OP_SEND` via the same SQE template.

**Net loss for small responses.** The 88-byte HTTP 200 response is too small to benefit from zero-copy. The DMA setup overhead exceeds the copy cost. See `docs/zerocopy.md` for analysis.

## Multicore

`server_start()` in `src/event.c`, gated behind `#ifdef MULTICORE`.

**Worker spawn.** N workers via raw `clone()` syscall 56 (asm trampoline `thread_create()` in `nolibc.h`). Clone flags: `CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID`. Notably **no `CLONE_FILES`** — each worker gets its own file descriptor table.

**Per-worker isolation.** Each worker owns:
- Listen socket (separate `socket()` + `bind()` + `listen()` with `SO_REUSEPORT`)
- io_uring (separate `uring_init`)
- Fixed file table (separate `uring_register_fixed_files`)
- Buffer rings (separate `buf_ring_mgr_init`)
- `struct worker_data` — 832KB mmap'd region containing:
  - `conn_state[65536]` — 64KB (1 byte per connection)
  - `idle_node[65536]` — 256KB (4 bytes per connection)
  - `last_activity[65536]` — 512KB (8 bytes per connection)

**CPU stride-2.** Workers are pinned to CPUs `cpu_start, cpu_start+2, cpu_start+4, ...`, skipping HT siblings. One worker per physical core avoids HT contention.

**Futex join.** `CLONE_CHILD_CLEARTID` causes the kernel to write 0 to `worker_info.tid_futex` on thread exit and wake futex waiters. The main thread loops on `sys_futex_wait()` until all workers have exited before unmapping their memory.

**Shared shutdown.** `volatile sig_atomic_t g_shutdown` is the only shared state. Signal handlers (SIGINT/SIGTERM) set it to 1. Workers check it in the event loop condition. No locks needed — it's a monotonic flag.

**Stack allocation.** Each worker gets a 64KB mmap'd stack (`MAP_STACK`).

## Signal Handling and Shutdown

`signal_handler()` sets `g_shutdown = 1`. Installed for SIGINT and SIGTERM via `k_sigaction()` in `nolibc.h`, which wraps `sys_rt_sigaction` with the required `SA_RESTORER` trampoline (kernel mandates this on x86-64).

The event loop checks `ctx->running && !g_shutdown` each iteration. `uring_submit_and_wait()` returns `-EINTR` when a signal arrives during the syscall; this is handled as a non-fatal return.

Currently there is no graceful drain — in-flight requests are abandoned when the loop exits. See `docs/roadmap.md` section 3 for the planned drain sequence.

## FILE_IO Mode

`#ifdef FILE_IO` adds three op types (`OP_FILE_READ`, `OP_FILE_WRITE`, `OP_FILE_FSYNC`) with corresponding SQE templates and handler stubs. The templates and `PREP_SQE_FILE` macro are functional, but the handlers only log errors — they are not wired into the request/response pipeline. This is infrastructure for a future file-serving mode.

## Conn_state Guard Bits

`struct conn_state` in `src/event.c` — 1 byte per fd, bit-packed:

| Bit | Name | Purpose |
|-----|------|---------|
| 0 | `closing` | Blocks new ops (recv, send) for this connection. Set at start of close sequence, cleared when close CQE completes. |
| 1 | `recv_active` | Prevents duplicate multishot recv. Set when recv is queued, cleared when multishot terminates (MORE absent). |
| 2 | `cancel_sent` | Prevents double-cancel. Set when ASYNC_CANCEL is submitted, cleared on close completion. |
| 3 | `in_idle` | Tracks LRU list membership. Set on idle_touch, cleared on idle_remove. Checked before unlink to avoid corrupting the list. |

In non-multicore mode, `conn_state` is a BSS global array (zero-initialized by kernel ELF loader). In multicore mode, it's part of `struct worker_data` (mmap'd with `MAP_ANONYMOUS`, zeroed by kernel).
