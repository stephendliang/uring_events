# io_uring DNS Resolver

Async DNS resolution directly from the reactor. Raw UDP via io_uring, hand-built DNS packets, zero libc dependency. Prereq for the crawler but useful standalone — any outbound connection needs name resolution.

## Current state

The reactor has no outbound connection support at all. No `IORING_OP_CONNECT`, no UDP ops, no DNS. The server accepts inbound TCP only. This plan adds:

1. UDP send/recv ops to the reactor (`IORING_OP_SENDMSG` / `IORING_OP_RECVMSG`)
2. DNS wire format builder/parser
3. Async resolution integrated into the event loop

## DNS wire format

DNS is simple enough to implement without a library. A query is ~30-50 bytes, a response fits in 512 bytes (or 4096 with EDNS0).

### Query packet layout

```
Bytes   Field
0-1     Transaction ID (random u16)
2-3     Flags: 0x0100 (standard query, recursion desired)
4-5     QDCOUNT: 1
6-7     ANCOUNT: 0
8-9     NSCOUNT: 0
10-11   ARCOUNT: 0 (or 1 with EDNS0 OPT record)
12+     QNAME: length-prefixed labels (e.g., \x06google\x03com\x00)
+2      QTYPE: 0x0001 (A) or 0x001C (AAAA)
+2      QCLASS: 0x0001 (IN)
```

Total: 12-byte header + encoded hostname + 4 bytes. Building this is ~20 lines of C — encode labels, append type/class, done.

### Response parsing

```
Header (12 bytes) → skip to answer section
For each answer RR:
  NAME:     2 bytes if compressed (0xC0xx pointer), else label sequence
  TYPE:     2 bytes (A=1, AAAA=28, CNAME=5)
  CLASS:    2 bytes
  TTL:      4 bytes
  RDLENGTH: 2 bytes
  RDATA:    4 bytes (A) or 16 bytes (AAAA) or name (CNAME)
```

Key details:
- **Name compression**: pointers (top 2 bits = 11) reference earlier in the packet. Must follow pointers to resolve CNAMEs but cap recursion depth to prevent loops.
- **CNAME chasing**: if the answer is a CNAME, look for the next RR that resolves the canonical name. Servers usually include the A record after the CNAME in the same response.
- **Truncation (TC bit)**: if set, response was truncated at 512 bytes. Retry over TCP. Rare for simple A/AAAA queries.
- **EDNS0**: add OPT pseudo-RR in additional section to advertise 4096-byte UDP payload. Avoids truncation for most responses.

## New io_uring ops needed

### IORING_OP_SENDMSG (opcode 9)

Sends a UDP datagram via `struct msghdr`. SQE fields:

```c
struct io_uring_sqe {
    .opcode   = IORING_OP_SENDMSG,  // 9
    .fd       = socket_fd,
    .addr     = (u64)&msghdr,       // points to struct msghdr
    .len      = 1,                   // nr_msgs (typically 1)
    .msg_flags = 0,                  // MSG_* flags
};
```

The `msghdr` points to the destination sockaddr and the iovec with the DNS query bytes. For a fixed resolver IP, the msghdr can be a template — only the iovec base/len and transaction ID change per query.

### IORING_OP_RECVMSG (opcode 10)

Receives a UDP datagram. Same shape, msghdr provides the receive buffer.

```c
struct io_uring_sqe {
    .opcode   = IORING_OP_RECVMSG,  // 10
    .fd       = socket_fd,
    .addr     = (u64)&msghdr,       // msghdr with iovec pointing to recv buffer
    .len      = 1,
    .msg_flags = 0,
};
```

**Multishot recvmsg** (`IORING_RECV_MULTISHOT` in ioprio): available since kernel 6.0. Single SQE, multiple CQEs as datagrams arrive. Works with provided buffer rings — each incoming datagram consumes a buffer from the ring. This is the preferred model: one persistent recvmsg SQE on the DNS socket, responses arrive as CQEs with buffer IDs.

### IORING_OP_SOCKET (opcode 45)

Async socket creation. Optional — could just use synchronous `socket()` at startup since we only need one or two UDP sockets. But if we want the entire DNS flow to be async from socket creation through resolution:

```c
struct io_uring_sqe {
    .opcode     = IORING_OP_SOCKET,  // 45
    .fd         = AF_INET,           // domain
    .off        = SOCK_DGRAM,        // type
    .len        = 0,                 // protocol
    .file_index = slot,              // direct descriptor
};
```

### SQE templates

New templates in event.c (or a future dns.c):

```c
CACHE_ALIGN
static const struct io_uring_sqe SQE_TEMPLATE_DNS_SEND = {
    .opcode = IORING_OP_SENDMSG,
    .flags  = IOSQE_FIXED_FILE,
    .len    = 1,
};

CACHE_ALIGN
static const struct io_uring_sqe SQE_TEMPLATE_DNS_RECV = {
    .opcode    = IORING_OP_RECVMSG,
    .flags     = IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT,
    .ioprio    = IORING_RECV_MULTISHOT,
    .len       = 0,    // must be 0 for multishot
    .buf_group = DNS_BUFFER_GROUP_ID,
};
```

The SIMD `PREP_SQE` works for these — same pattern: copy template, patch fd + user_data. The msghdr pointer goes in `addr`, which means `PREP_SQE_FILE` or a new 3-field variant could handle it.

### user_data encoding

New op codes:

```c
OP_DNS_SEND = 11,
OP_DNS_RECV = 12,
```

The existing `[fd:32 | op:8 | buf_idx:16 | unused:8]` layout works. For DNS recv with provided buffers, `buf_idx` carries the buffer ID from CQE flags (same as TCP recv). Transaction ID matching uses the packet content, not user_data.

## DNS cache

```c
struct dns_entry {
    u64  name_hash;      // hash of the queried hostname
    u32  addr;           // IPv4 (or index into separate IPv6 table)
    u32  ttl_tsc;        // expiry in TSC ticks (reuse existing TSC infra)
    u16  txn_id;         // for matching pending queries
    u8   state;          // EMPTY / PENDING / RESOLVED / FAILED
    u8   _pad;
};
```

Fixed-size hash table, open addressing. Size: 4096 entries = 64KB. Lookup is one cache line read. No heap allocation.

**TTL handling**: convert DNS TTL (seconds) to TSC ticks using the existing `tsc_freq` from CPUID. Compare against `rdtsc()` on lookup — same pattern as idle sweep.

**Pending query dedup**: if a lookup for the same name is already in-flight (state=PENDING), don't send a second query. Park the caller's context (connection fd + callback op) in a small waitlist. When the response arrives, wake all waiters.

## Buffer ring for DNS

Add a third buffer group to `buf_ring_mgr`:

```
Group 0: TCP recv buffers (4096 × 2KB) — existing
Group 1: ZC notification   — existing (unused)
Group 2: DNS recv buffers  (64 × 512B = 32KB)
```

512 bytes per buffer handles standard DNS responses. With EDNS0 (4096-byte payloads), bump to 4KB buffers or handle truncation + TCP fallback.

`BUF_RING_MAX_GROUPS` in uring.h goes from 2 → 3.

## Integration with event loop

Two approaches:

### Option A: DNS in the server event loop

Add DNS socket + handlers directly to the existing `event_loop` CQ drain. The DNS socket is just another fd with its own op codes. CQE dispatch in the existing switch statement grows by two cases.

Pros: no new code paths, reuses everything.
Cons: DNS logic in event.c makes it server-specific.

### Option B: Separate DNS module

```
src/dns.h    — public API: dns_resolve(name, callback_ud), dns_init(), dns_process_cqe()
src/dns.c    — packet build/parse, cache, query state machine
```

The reactor calls `dns_process_cqe()` from the CQ drain when it sees `OP_DNS_SEND` or `OP_DNS_RECV`. The DNS module queues SQEs via the existing `get_sqe()` + `PREP_SQE()`.

Pros: modular, reusable across server and crawler.
Cons: needs a way to pass the uring ring pointer to the DNS module.

**Recommended: Option B.** Pass `struct uring_sq *sq` + `struct buf_ring *dns_bufs` to `dns_init()`. The DNS module owns its socket fd and query state, but I/O goes through the shared ring.

## Resolution flow

```
1. dns_resolve("example.com", user_data_for_callback)
2.   → cache lookup (hash table probe)
3.   → HIT + valid TTL: return immediately, queue CONNECT with resolved addr
4.   → MISS or EXPIRED:
5.       → build DNS query packet (A record)
6.       → get_sqe() + PREP_SQE(dns_send_template, dns_fd, encode(OP_DNS_SEND, txn_id))
7.       → set cache entry to PENDING, store caller's user_data in waitlist
8.
9. [... event loop continues ...]
10.
11. CQE arrives for OP_DNS_RECV:
12.   → parse response from provided buffer
13.   → match txn_id to cache entry
14.   → extract A/AAAA record, store in cache with TTL
15.   → wake waiters: for each parked caller, queue IORING_OP_CONNECT with resolved addr
16.   → recycle DNS buffer back to ring
```

## Retry and failure

- **Timeout**: if no response in 2 seconds, retransmit (same txn_id). Max 3 attempts.
- **SERVFAIL / NXDOMAIN**: mark cache entry FAILED with negative TTL (60s). Don't retry.
- **Truncation (TC=1)**: fall back to TCP. This requires CONNECT + SEND + RECV for a single DNS query — heavier but rare.
- **Multiple resolvers**: try secondary resolver on timeout. Configure as array of sockaddrs.

Timeout tracking reuses the existing RDTSC + sweep pattern. Either piggyback on the idle sweep timer (check DNS timeouts every 5s — coarse but free) or add a dedicated `IORING_OP_TIMEOUT` for DNS with a 2s interval.

## Phases

**Phase 1 — UDP ops + raw DNS query/response**
- Add SENDMSG/RECVMSG SQE templates and op codes
- DNS packet builder (A queries only)
- DNS response parser (A records, CNAME following)
- Synchronous-style test: resolve a name, print the IP, exit
- Buffer group 2 for DNS recv

**Phase 2 — Async integration**
- dns.h/dns.c module with `dns_resolve()` / `dns_process_cqe()`
- Cache with TTL
- Pending query dedup + waiter list
- Timeout + retry

**Phase 3 — Production hardening**
- EDNS0 OPT record (4096 byte payload)
- AAAA (IPv6) support
- TCP fallback for truncated responses
- Multiple resolver support
- Negative caching

## Open questions

- **Resolver config**: hardcode 8.8.8.8 / 1.1.1.1? Parse /etc/resolv.conf at startup (breaks freestanding purity but is practical)? CLI arg?
- **IPv6**: dual-stack from the start, or IPv4-only for phase 1? AAAA parsing is trivial but connect/sockaddr handling doubles.
- **DNS-over-HTTPS / DNS-over-TLS**: blocks on TLS support (see crawler.md). Skip until TLS exists.
- **Cache eviction**: fixed 4096 slots with open addressing means eviction on collision. LRU? Or just overwrite oldest TTL entry in the probe chain?
