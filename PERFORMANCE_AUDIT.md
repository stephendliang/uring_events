# Performance Audit: event.c + uring.h

## Overview

This document provides a comprehensive performance analysis of the io_uring HTTP server implementation. Issues are categorized by severity and include specific line references and remediation guidance.

**Last Updated:** After P2 optimizations (IOSQE_CQE_SKIP_SUCCESS, conditional buf_ring_sync, switch dispatch)

---

## CRITICAL ISSUES

### 1. Buffer Ring Tail Batching - FIXED

**Location:** `uring.h:357-374`

**Original Problem:**
```c
static inline void buf_ring_recycle(struct buf_ring *br, uint16_t bid) {
    ...
    br->tail = tail + 1;
    smp_store_release(&br->br->tail, br->tail);  // BARRIER ON EVERY BUFFER!
}
```

**Impact:** O(completions) memory barriers per event loop iteration instead of O(1).

**Fix Applied:**
1. `buf_ring_recycle()` now only updates local tail (no barrier)
2. Added `buf_ring_sync()` that issues single `smp_store_release`
3. Event loop calls `buf_ring_sync()` conditionally after CQE batch processing

```c
// uring.h - split into two functions
static inline void buf_ring_recycle(struct buf_ring *br, uint16_t bid) {
    ...
    br->tail = tail + 1;
    /* NO barrier - call buf_ring_sync() after batch */
}

static inline void buf_ring_sync(struct buf_ring *br) {
    smp_store_release(&br->br->tail, br->tail);
}

// event.c:589-591 - conditional sync
if (ctx->br.tail != br_tail_start)
    buf_ring_sync(&ctx->br);
```

**Status:** COMPLETE

---

### 2. Prefetch Strategy Needs Revision

**Location:** `event.c:558`

**Current code:**
```c
prefetch_r(&cqes[(head + 1) & cq_mask]);
```

**Analysis:**

The CQE array prefetch is **redundant**. Modern CPUs have hardware L2 streamer prefetchers that detect sequential access patterns and prefetch ahead automatically. CQEs are 16 bytes, so 4 fit per 64-byte cache line - the hardware handles sequential array traversal.

However, prefetching the **connection state** would be useful. The `g_conns[fd]` access pattern is essentially random - fd values depend on accept order, connection lifetimes, and fd recycling. The hardware prefetcher cannot predict this. This is a dependent load that could stall the pipeline.

**Impact:** Cache misses on connection state access, not on CQE access.

**Fix:** Replace CQE prefetch with connection state prefetch:

```c
// Prefetch conn state for NEXT iteration (random access pattern)
struct io_uring_cqe *next_cqe = &cqes[(head + 1) & cq_mask];
int32_t next_fd = decode_fd(next_cqe->user_data);
if (next_fd >= 0 && next_fd < MAX_CONNECTIONS)
    prefetch_r(&g_conns[next_fd]);
```

This reads ahead in the CQE array to get the next fd, then prefetches that connection state. The CQE read itself benefits from hardware prefetching; the connection state does not.

**Alternative:** Remove prefetching entirely if profiling shows it doesn't help. The current CQE prefetch is likely a no-op.

---

## MODERATE ISSUES

### 3. IOSQE_CQE_SKIP_SUCCESS For TCP_NODELAY - FIXED

**Location:** `event.c:241`

**Original Problem:**
The setsockopt for TCP_NODELAY generated a CQE that had to be processed, but success is fire-and-forget. This wasted CQ space and processing cycles.

**Fix Applied:**
```c
sqe->flags = IOSQE_CQE_SKIP_SUCCESS;  /* No CQE on success - reduces CQ pressure */
```

Only generates CQE on failure, which is still handled.

**Status:** COMPLETE

---

### 4. Missing TCP_QUICKACK

**Location:** `event.c:431`

**Problem:**
For request-response patterns, delayed ACKs add latency. Currently only TCP_NODELAY is set.

**Impact:** Up to 40ms additional latency per request due to delayed ACK timer (depends on kernel config).

**Fix:** Queue an additional setsockopt for TCP_QUICKACK:

```c
static int g_tcp_quickack_val = 1;

// In handle_accept:
queue_setsockopt(ctx, fd, IPPROTO_TCP, TCP_QUICKACK,
                 &g_tcp_quickack_val, sizeof(g_tcp_quickack_val));
```

**Caveat:** TCP_QUICKACK is not persistent and may need re-setting after recv. Evaluate if latency improvement justifies the overhead.

---

### 5. One-Second Wait Timeout

**Location:** `event.c:529`

**Problem:**
```c
struct __kernel_timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
```

Under idle conditions, shutdown will be delayed up to 1 second after SIGINT/SIGTERM.

**Impact:** Poor shutdown responsiveness during idle periods.

**Fix:** Reduce to 100ms or use `signalfd` registered with io_uring:

```c
struct __kernel_timespec ts = { .tv_sec = 0, .tv_nsec = 100000000 };  // 100ms
```

Or integrate signal handling into the event loop via `signalfd` + `IORING_OP_READ`.

---

## MINOR ISSUES

### 6. No NAPI Busy Polling

**Location:** N/A (missing feature)

**Problem:**
For sub-microsecond latency requirements, interrupt-driven completion adds latency variance. NAPI busy polling can reduce this.

**Impact:** Higher latency variance under light load due to interrupt coalescing.

**Fix:** Consider `SO_BUSY_POLL` on sockets or `IORING_REGISTER_NAPI` (kernel 6.3+).

---

### 7. ENOBUFS Handling May Spin

**Location:** `event.c:463-466`

**Problem:**
```c
} else if (res == -ENOBUFS) {
    LOG_WARN("ENOBUFS fd=%d", fd);
    if (!more && c && !c->closing)
        queue_recv(ctx, fd);
}
```

Under sustained buffer exhaustion, this creates a tight retry loop with no backoff.

**Impact:** CPU spin under memory pressure, potential livelock.

**Fix:** Implement exponential backoff or connection-level backpressure:

```c
// Option 1: Track ENOBUFS count per connection, close after N failures
// Option 2: Use io_uring timeout to delay re-queue
// Option 3: Implement connection-level backpressure (stop accepting)
```

---

### 8. Connection State Array False Sharing Potential

**Location:** `event.c:104`

**Problem:**
```c
static struct conn_state g_conns[MAX_CONNECTIONS];
```

Each connection state is 1 byte. 64 adjacent FDs share a single cache line.

**Impact:** Under multi-worker scaling with separate rings, workers accessing adjacent FDs cause false sharing. **Not a concern for single-worker deployment.**

**Fix (for multi-worker):** Pad to cache line or at minimum 8 bytes:

```c
struct conn_state {
    uint8_t closing : 1;
    uint8_t recv_active : 1;
    uint8_t reserved : 6;
    uint8_t padding[7];  // Pad to 8 bytes
};
```

Or use `__attribute__((aligned(64)))` for full cache line isolation.

---

## THINGS DONE CORRECTLY

| Aspect | Status |
|--------|--------|
| io_uring flags match CLAUDE.md spec | ✓ |
| Multishot accept/recv properly implemented | ✓ |
| CQ drain uses correct acquire-release semantics | ✓ |
| CQ head update is correctly batched | ✓ |
| Switch dispatch enables inlining + direct branches | ✓ |
| No malloc in hot path | ✓ |
| Async close (no `close(2)` syscall in hot path) | ✓ |
| Async setsockopt via `IORING_OP_URING_CMD` | ✓ |
| Buffer index extraction via shift (no division) | ✓ |
| Static response avoids formatting overhead | ✓ |
| `likely()`/`unlikely()` hints appropriately placed | ✓ |
| x86-TSO optimized memory barriers | ✓ |
| Provided buffer ring with huge pages | ✓ |
| O(1) SQ submit via identity mapping | ✓ |
| Conditional buf_ring_sync (no write if no recycles) | ✓ |
| IOSQE_CQE_SKIP_SUCCESS on fire-and-forget ops | ✓ |

---

## PRIORITY RANKING FOR REMAINING FIXES

| Priority | Issue | Expected Impact | Complexity |
|----------|-------|-----------------|------------|
| 1 | Prefetch conn state (not CQE) | Reduced cache misses | Low |
| 2 | TCP_QUICKACK | Lower request latency | Low |
| 3 | Timeout reduction (1s → 100ms) | Better shutdown responsiveness | Trivial |
| 4 | ENOBUFS backoff | Stability under pressure | Medium |
| 5 | Connection state padding | Multi-worker scaling | Low |
| 6 | NAPI busy polling | Latency variance reduction | Medium |

---

## DESIGN ANALYSIS: Embedding conn_state in user_data

### Question
Could we eliminate the `g_conns[fd]` cache miss by embedding connection state directly in the 64-bit user_data field?

### Current Bit Allocation
```
[fd:32][op:8][buf_idx:16][unused:8] = 64 bits
```

### Minimum Bits Actually Needed
| Field | Current | Minimum | Notes |
|-------|---------|---------|-------|
| fd | 32 bits | 20 bits | 1M fds is way more than enough |
| op | 8 bits | 3 bits | Only 5 operations (0-4) |
| buf_idx | 16 bits | 12 bits | NUM_BUFFERS=4096 |
| conn_state | N/A | 2 bits | closing + recv_active |
| **Total** | 64 bits | **37 bits** | 27 bits unused! |

### Verdict: NOT FEASIBLE

The problem is **mutability**. Connection state changes between SQE submission and CQE completion:

1. We queue a recv → user_data encodes `closing=0`
2. Error occurs → we set `closing=1` and queue close
3. Recv CQE arrives → its user_data still says `closing=0` (stale!)

The `closing` flag is a "poison" marker that must be checked at CQE processing time against *current* state, not submission-time state.

### Conclusion
Prefetching the connection state is the right solution. The `g_conns` array (64KB for 65536 connections at 1 byte each) fits in L2 cache. Under steady-state operation, active entries stay hot. The prefetch helps when working set exceeds L1.
