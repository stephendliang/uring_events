# Zero-Copy Send: Why It's Worthless for Small Responses

**Date**: 2026-02-21
**Kernel**: 6.19.2-2-cachyos
**Hardware**: i9-12900HK, Intel I219-V (1GbE), isolcpus=4-11

## The Promise

`IORING_OP_SEND_ZC` sounds like free performance. Instead of copying your
buffer into the kernel's socket buffer, the kernel pins your memory and
DMAs directly from it. No copy. Zero. Hence the name.

So we wired it up. Probed the kernel, allocated notification tracking,
handled the two-phase completion dance. Built the whole thing. Benchmarked
it.

It made the server slower.

## The Results

**LAN — MacBook (wrk) → server over 1GbE, 4 workers on isolated cores:**

| Conns | Regular Send | ZC Send | Throughput Delta | Latency Delta |
|-------|-------------|---------|------------------|---------------|
| 100 | 112K req/s, 0.90ms | 120K req/s, 0.98ms | +7% (noise) | +9% worse |
| 1000 | 245K req/s, 4.01ms | 244K req/s, 4.05ms | -0.4% (noise) | +1% (noise) |
| 4000 | 241K req/s, 7.86ms | 236K req/s, 10.74ms | -2% | **+37% worse** |

At 4000 connections, ZC added almost 3ms of latency for nothing. At every
concurrency level, it was either noise or a regression.

## Why This Happens

Here's the thing people miss about zero-copy: **it doesn't eliminate work,
it trades one kind of work for another.** You stop copying bytes, but you
start tracking buffer lifetime. The kernel needs to know when it's safe
for you to reuse that memory. That tracking has a cost.

### What regular SEND does

```
userspace buffer  --memcpy-->  kernel socket buffer  --DMA-->  NIC
                   ~2 cycles
                   (88 bytes = 1 cache line)
```

One `memcpy`. For 88 bytes, that's moving a single cache line that's
already hot in L1. Two cycles. Maybe three. It's so fast the CPU doesn't
even notice.

### What SEND_ZC does

```
1. Submit SEND_ZC SQE
2. Kernel calls io_alloc_notif() — allocate notification tracker
3. Kernel pins your buffer page
4. DMA from your buffer
5. Kernel delivers completion CQE #1 (send done, but buffer still in use)
6. NIC finishes transmitting
7. Kernel delivers CQE #2 (NOTIF — buffer is now safe to reuse)
8. You decrement your inflight counter
```

Seven extra steps to avoid a 2-cycle memcpy. Every single SEND_ZC
produces **two CQEs** instead of one. The notification in step 2
allocates a full `io_kiocb` (~256 bytes) from the io_uring request
slab — and under load it fails with ENOMEM, requiring a fallback to
regular send anyway.

### The arithmetic doesn't lie

The copy cost for an 88-byte response:

```
88 bytes / 64 bytes per cache line = 1.375 cache lines
L1 hit latency: ~1ns
Total copy cost: ~2-3ns
```

The notification overhead per SEND_ZC:

```
io_kiocb slab alloc for notif: ~20-50ns
Extra CQE processing: ~10-20ns
Inflight counter atomic: ~5ns
Total overhead: ~35-75ns
```

You're paying **35-75ns of overhead to save 2-3ns of copying.** That's
not optimization. That's a net loss of 30-70ns per send. Multiply by
245,000 requests/second and you're burning 7-17ms of CPU time per second
on pure overhead.

### Why it gets worse at high concurrency

At 4000 connections, two things compound:

1. **ENOMEM from notification allocation.** Each SEND_ZC calls
   `io_alloc_notif()`, which allocates a full `io_kiocb` request struct
   (~256 bytes) from the per-ring request cache. That's the same slab
   cache used for every io_uring operation. A single ZC send consumes
   **two** `io_kiocb` objects — one for the send, one for the
   notification — doubling the request object pressure versus regular
   send.

   Under high concurrency, this allocation fails and returns `-ENOMEM`
   to your CQE. At 1000 localhost connections without any cap, we
   observed **169,000 ENOMEM errors** in a 5-second benchmark. The
   server had to fall back to regular send for each one — but only
   after paying the cost of attempting ZC first.

2. **Double CQE pressure.** Every ZC send produces two CQEs. At 4000
   connections that doubles CQ ring pressure, increasing the chance
   of CQ overflow and adding latency to the completion processing loop.

The 37% latency regression at 4000 connections is not a mystery. It's
exactly what you'd expect.

### Can you fix the ENOMEM?

No. Not without kernel changes, and probably not even then.

**There's no tunable.** No sysctl, no `io_uring_register` opcode, no
pre-allocation API. The kernel used to have one — the initial ZC
patchset (5.19-rc) included `IORING_REGISTER_NOTIFIERS` which let
userspace register notification slots explicitly. It was
[removed before 6.0](https://lwn.net/Articles/906803/) because the API
was too complex. The replacement is implicit per-request allocation:
every SEND_ZC internally allocates its notification, and if that fails,
you get ENOMEM. No negotiation.

**The allocation isn't even `GFP_NOWAIT`.** It uses
`GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO` — the most permissive context.
It *can* sleep, *can* trigger direct reclaim, *can* invoke the OOM
killer. If it's still failing, you're either hitting `RLIMIT_MEMLOCK`
(the `io_notif_account_mem()` path checks the per-user locked memory
budget) or you're genuinely exhausting the slab under extreme request
rates.

**Raising `ulimit -l` might reduce failures** but won't eliminate them.
The locked memory accounting charges pages for each notification's
buffer pinning. At 1000+ concurrent ZC sends, each pinning at least one
page, you're locking 4MB+ of memory just for notification tracking. The
real fix is to not have thousands of concurrent notifications in flight.

**Our mitigation: `ZC_MAX_INFLIGHT=256`.** A per-worker cap on
outstanding ZC sends. When the cap is hit, `handle_recv` falls back to
regular send proactively — no ENOMEM, no wasted submission attempt. This
reduced errors from 169K to zero. But it also means at high concurrency,
most sends go through the regular path anyway, making ZC a
sometimes-optimization with always-present complexity.

## When ZC Actually Wins

Zero-copy is not useless. It's useless **for this workload.** The
crossover point is roughly:

```
copy_cost > notification_overhead
bytes * per_byte_cost > ~50ns
bytes > ~4000  (assuming ~12ns/cacheline L1->socket buffer)
```

ZC makes sense when:

- **Response bodies are large** (file serving, proxied responses, video
  streaming) — 4KB+ where the copy cost is measured in microseconds,
  not nanoseconds
- **The NIC is fast** (10GbE, 25GbE, 100GbE) — 1GbE saturates at 245K
  req/s with small packets regardless of send method
- **You're CPU-bound, not NIC-bound** — if the NIC is the ceiling, ZC
  can't raise it

Our server sends an 88-byte static response over 1GbE. We hit all three
anti-patterns: tiny payload, slow NIC, network-bound. ZC is the wrong
tool.

## Current Status

The ZC infrastructure is compiled in unconditionally but gated at runtime.
`buf_ring_zc_probe()` checks for kernel support; if absent, `ctx->zc_grp`
is NULL and `ctx_zc_enabled()` returns false — regular send path, zero
overhead. The infrastructure exists for future workloads (large-body file
serving over faster NICs) where the copy cost actually matters.

Components present:

| Component | Purpose | Status |
|-----------|---------|--------|
| `SQE_TEMPLATE_SEND_ZC` | SIMD SQE template | Ready |
| `queue_send_zc()` | Submit ZC send | Ready |
| `handle_send_zc()` | Two-phase completion + ENOMEM fallback | Ready |
| `ZC_MAX_INFLIGHT` cap | Prevent kernel ENOMEM under load | Ready |
| `buf_ring_zc_probe()` | Runtime kernel capability check | Ready |
| ZC buffer group init | Provided buffer ring for ZC sends | Ready |

## The Lesson

Zero-copy sounds fast because copying sounds slow. But "copy" is not a
single operation with a single cost — it scales with size. At 88 bytes
the copy is invisible. The bookkeeping to avoid it is not.

Always measure. The name of the optimization is not the optimization.
