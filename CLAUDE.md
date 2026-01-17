# uring_server

A shared-nothing, io_uring-native TCP+TLS server designed for predictable tail latencies and linear core scaling.

**No epoll. No thread pools. No locks.**

## Core Architecture

### Shared-Nothing Per-Core Isolation

Each worker owns exactly one CPU core, one `io_uring` instance, and one set of listening/connected sockets. There is no cross-core communication in the hot path.

- Memory allocators are core-local
- Connection state never migrates
- Core affinity enforced via `sched_setaffinity(2)` + `SO_INCOMING_CPU`
- RSS or `SO_ATTACH_REUSEPORT_CBPF` ensures packets land on the correct core-assigned RX queue
- Context switches in steady-state: **zero**

### No liburing

We do not use `liburing` to minimize overhead and expose `io_uring` internals directly. Code examples in this document use liburing-style pseudocode for clarity, but the actual implementation uses raw syscalls and ring manipulation.

### io_uring Configuration

| Flag | Rationale |
|------|-----------|
| `IORING_SETUP_SUBMIT_ALL` | All-or-nothing submission; prevents partial SQE commits |
| `IORING_SETUP_SINGLE_ISSUER` | Kernel skips submission locking (single-threaded access) |
| `IORING_SETUP_DEFER_TASKRUN` | Completions batch in kernel; runs only on `submit_and_wait_timeout` |
| `IORING_SETUP_COOP_TASKRUN` | No async TWA interrupts; we control task_work execution |
| `IORING_SETUP_CQSIZE` | CQ sized to 4× SQ depth; prevents overflow under burst |

**SQPOLL is explicitly avoided.** Kernel polling threads burn CPU and fight for cache with userspace.

## Event Loop

Single-syscall submit/wait pattern:

```c
io_uring_submit_and_wait_timeout(&ring, &cqe, 1, &ts, NULL);
```

CQ drain via direct ring access (no `peek_batch_cqe` indirection):

```c
unsigned head = *ring.cq.khead;
unsigned tail = io_uring_smp_load_acquire(ring.cq.ktail);
while (head != tail) {
    io_uring_cqe* cqe = &ring.cq.cqes[head & ring.cq.ring_mask];
    // process
    ++head;
}
io_uring_smp_store_release(ring.cq.khead, head);
```

Acquire-release semantics match kernel expectations; no stronger barriers required on x86-TSO.

## Key Patterns

### Multishot Accept

Single SQE generates unbounded CQEs until cancelled:

```c
io_uring_prep_multishot_accept(sqe, listen_fd, NULL, NULL, 0);
```

- CQEs arrive with `IORING_CQE_F_MORE` until cancellation or error
- Backpressure is implicit: if CQ fills, accept stalls

### Multishot Receive

Paired with provided buffer rings:

```c
io_uring_prep_recv_multishot(sqe, client_fd, NULL, 0, 0);
sqe->flags |= IOSQE_BUFFER_SELECT;
sqe->buf_group = BUF_GROUP_ID;
```

Buffer ID extracted from `cqe->flags >> IORING_CQE_BUFFER_SHIFT`.

### TLS Record Bundling

Nagle's algorithm is disabled (`TCP_NODELAY`). Multiple TLS records coalesced via `MSG_MORE`:

```c
// N-1 sends with MSG_MORE
io_uring_prep_send(sqe, fd, tls_record[i], len, MSG_MORE);
// final send without MSG_MORE flushes
io_uring_prep_send(sqe, fd, tls_record[N-1], len, 0);
```

### Rate Limiting

Client sockaddr captured at accept time, hashed into per-core rate limit table.

- Rate decisions occur **before** buffer allocation
- Exceeding connections get 429 + immediate close (no recv buffer, no TLS handshake)
- Sliding window counter with sub-millisecond bucket granularity
- IPv6 masked to /64 for prefix-based limiting
- LRU eviction driven by idle timeout tick (100ms interval)

## Memory Model

| Resource | Strategy |
|----------|----------|
| Connection state | Slab allocator, core-local, fixed-size slots |
| Recv buffers | Provided buffer ring, pre-faulted huge pages |
| Send buffers | Registered buffer pool, zero-copy when >MTU |
| sockaddr table | Open-addressed hash, inline storage, no heap alloc |

**All allocations occur at startup. The hot path is malloc-free.**

## Constraints

- **Not portable**: Linux 6.1+ required. Missing `io_uring` features are fatal.
- **Not a framework**: Application logic is compiled in.
- **Not QUIC**: TCP only. UDP requires different batching strategies.
- **Not vectored I/O**: Fixed-size buffers simplify accounting.

## Performance Targets

| Metric | Target |
|--------|--------|
| Syscalls per request | 0–1 (multishot amortized) |
| Context switches (steady state) | 0 |
| Locks acquired (hot path) | 0 |
| Cache misses per connection | 1 (state struct, pre-fetched) |
| Interrupt rate | O(completions / CQ batch size) |

Latency variance sources (all tunable, none architectural):
- Kernel scheduler noise → mitigate with `isolcpus`
- NIC interrupt coalescing → tune via `ethtool`
- CQ drain batching → bounded by timeout
