# Reactor Feature Roadmap

Status of planned features for the io_uring TCP reactor (`src/event.c`).

| #  | Feature                     | Status      |
|----|-----------------------------|-------------|
| 1  | Cancel-on-close             | Done        |
| 2  | Idle connection sweep       | Done        |
| 3  | Graceful shutdown drain     | Planned     |
| 4  | Per-connection send queue   | Planned     |
| 5  | Dynamic buffer scaling      | Planned     |
| 6  | Multi-core (SO_REUSEPORT)   | Done        |
| 7  | TLS offload (kTLS)          | Planned     |
| 8  | HTTP request parsing        | Planned     |

---

## 1. Cancel-on-close (Done)

Before closing, issue `IORING_OP_ASYNC_CANCEL` targeting the active multishot
recv's `user_data`. Prevents orphaned CQEs from arriving after the fd slot
is reused by a new accept. Close deferred until cancel CQE arrives. If recv
is not active, close proceeds immediately. `cancel_sent` bit prevents
double-cancellation. SQ-full fallback reinserts into idle LRU for retry.

## 2. Idle connection sweep (Done — LRU; migrating to timing wheel)

**Current**: `IORING_OP_TIMEOUT` with `IORING_TIMEOUT_MULTISHOT` fires every
5 seconds. Walks an intrusive doubly-linked LRU list from head (oldest)
comparing `rdtsc()` against `last_activity[fd]` + `idle_timeout_ticks`
(precomputed from CPUID-detected TSC frequency × 30s). Walk stops at the
first non-expired node. Expired connections closed via cancel-on-close path.
All list operations O(1); sweep is O(k) where k = expired count.

### Benchmark findings (`bench_conn.c`)

At 1M connections, LRU touch degrades to 47 cyc/op (pointer-chasing
destroys caches) while alternatives stay flat at 6-8 cyc/op. LRU is
dominated at every connection count. Three alternatives were benchmarked:

| Strategy | Touch (1M) | Sweep (1M) | Footprint (1M) |
|----------|-----------|------------|----------------|
| **Wheel** | 8 cyc/op | 1.1M cyc (374us) | 2MB |
| Linear | 8 cyc/op | 1.3M cyc (450us) | 9MB |
| Sieve | 7 cyc/op | 2.1M cyc (708us) | 1.1MB |

**Timing wheel** is the Pareto winner: tied for touch, fastest sweep, small
footprint. Touch stores `(u8)(rdtsc() >> shift)` — single byte write, no
linked list. Sweep does a sequential u8 scan with modular epoch comparison.
Shift calibrated from TSC frequency at startup for ~1.5s buckets; timeout
precision is ±1 bucket.

**Planned migration**: replace `idle_node[]` doubly-linked list with
`u8 epoch[]` array. Eliminates 8 bytes/conn of idle tracking overhead
(prev/next pointers) and the `in_idle` flag bit. Sweep changes from
LRU-ordered walk to sequential scan of `epoch[]`.

## 3. Graceful shutdown drain (Planned)

On SIGINT/SIGTERM, stop accepting new connections but let in-flight
requests complete. Walk `conns[]` and `queue_close()` every active
connection. Wait for all CQEs to drain (close completions) before
tearing down the ring. Requires a `shutdown_phase` enum and a pending
connection counter.

Currently: `g_shutdown` flag causes immediate event loop exit. In-flight
requests are abandoned when the ring is destroyed.

## 4. Per-connection send queue (Planned)

Currently each recv triggers a single fixed HTTP 200 response. To support
real request/response pipelines, each connection needs a small send queue
(ring buffer of iovecs or SQE descriptors). Backpressure: if the send
queue is full, stop issuing recv SQEs for that connection (flow control
via multishot recv rearm suppression).

## 5. Dynamic buffer scaling (Planned)

The provided buffer ring is statically sized at compile time. Under load
spikes the ring can exhaust (`ENOBUFS`). Dynamic scaling would register
additional buffer groups on demand and retire them when load subsides.
Requires tracking ENOBUFS frequency and a hysteresis threshold to avoid
thrashing.

## 6. Multi-core / SO_REUSEPORT (Done)

Raw `clone()` syscall 56 spawns N workers, each with its own io_uring,
listen socket (`SO_REUSEPORT`), fixed file table, buffer rings, and
connection state. Shared-nothing: no locks, no cross-thread communication,
no `CLONE_FILES`. CPU stride-2 skips HT siblings. Futex-based join via
`CLONE_CHILD_CLEARTID`. Gated behind `#ifdef MULTICORE`.

See [multicore.md](multicore.md) for benchmarks.

## 7. TLS offload (kTLS) (Planned)

After accept, perform TLS handshake in userspace (or via a helper), then
install the negotiated keys into the kernel via `setsockopt(SOL_TLS)`.
Subsequent send/recv go through the kernel TLS module transparently.
io_uring ops remain the same — kTLS is transparent to the SQE layer.
Requires linking a minimal TLS library or implementing TLS 1.3 handshake
from scratch.

## 8. HTTP request parsing (Planned)

Replace the current "echo OK on any recv" logic with a minimal HTTP/1.1
request parser. Zero-copy: parse directly from the provided buffer ring
without copying into a separate request struct. Needs to handle partial
reads (request split across multiple recv completions) via a small
per-connection parser state machine. Keep-alive pipelining: after parsing
a complete request, check if more data follows in the same buffer.
