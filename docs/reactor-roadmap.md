# Reactor Feature Roadmap

Status of planned features for the io_uring TCP reactor (`src/event.c`).

| #  | Feature                     | Status      |
|----|-----------------------------|-------------|
| 1  | Cancel-on-close             | Done        |
| 2  | Idle connection sweep       | Done        |
| 3  | Graceful shutdown drain     | Planned     |
| 4  | Per-connection send queue   | Planned     |
| 5  | Dynamic buffer scaling      | Planned     |
| 6  | Multi-listener (SO_REUSEPORT) | Planned  |
| 7  | TLS offload (kTLS)          | Planned     |
| 8  | HTTP request parsing        | Planned     |

---

## 1. Cancel-on-close

Before closing a connection, issue `IORING_OP_ASYNC_CANCEL` targeting the
active multishot recv's `user_data`. This prevents orphaned CQEs from
arriving after the fd slot has been reused by a new accept. The close SQE
is deferred until the cancel CQE arrives. If the recv is not active, close
proceeds immediately. A `cancel_sent` bit in `conn_state` prevents double
cancellation.

## 2. Idle connection sweep

A single `IORING_OP_TIMEOUT` with `IORING_TIMEOUT_MULTISHOT` fires every
5 seconds. On each tick the handler reads `CLOCK_MONOTONIC`, updates
`g_cached_now`, and walks an intrusive doubly-linked LRU list from head
(oldest) to find connections whose last activity exceeds 30 seconds. The
walk stops at the first non-expired node (the list is sorted by time).
Expired connections are closed via the cancel-on-close path. All list
operations are O(1); the sweep is O(k) where k = number of expired
connections.

## 3. Graceful shutdown drain

On SIGINT/SIGTERM, stop accepting new connections but let in-flight
requests complete. Walk `g_conns[]` and `queue_close()` every active
connection. Wait for all CQEs to drain (close completions) before
tearing down the ring. Requires a `shutdown_phase` enum and a pending
connection counter.

## 4. Per-connection send queue

Currently each recv triggers a single fixed HTTP 200 response. To support
real request/response pipelines, each connection needs a small send queue
(ring buffer of iovecs or SQE descriptors). Backpressure: if the send
queue is full, stop issuing recv SQEs for that connection (flow control
via multishot recv rearm suppression).

## 5. Dynamic buffer scaling

The provided buffer ring is statically sized at compile time. Under load
spikes the ring can exhaust (`ENOBUFS`). Dynamic scaling would register
additional buffer groups on demand and retire them when load subsides.
Requires tracking ENOBUFS frequency and a hysteresis threshold to avoid
thrashing.

## 6. Multi-listener (SO_REUSEPORT)

Spawn N reactor threads, each with its own io_uring instance, pinned to
a distinct CPU core. Each thread creates its own listen socket with
`SO_REUSEPORT` so the kernel distributes incoming connections across
threads. Shared-nothing: no locks, no cross-thread communication.
Requires a top-level orchestrator that forks/clones threads and waits
for them.

## 7. TLS offload (kTLS)

After accept, perform TLS handshake in userspace (or via a helper), then
install the negotiated keys into the kernel via `setsockopt(SOL_TLS)`.
Subsequent send/recv go through the kernel TLS module transparently.
io_uring ops remain the same — kTLS is transparent to the SQE layer.
Requires linking a minimal TLS library or implementing TLS 1.3 handshake
from scratch.

## 8. HTTP request parsing

Replace the current "echo OK on any recv" logic with a minimal HTTP/1.1
request parser. Zero-copy: parse directly from the provided buffer ring
without copying into a separate request struct. Needs to handle partial
reads (request split across multiple recv completions) via a small
per-connection parser state machine. Keep-alive pipelining: after parsing
a complete request, check if more data follows in the same buffer.
