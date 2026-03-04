# io_uring Web Crawler

Faster curl-impersonate replacement. Async DNS + TLS + HTTP from the reactor core, no libc, no libcurl. Browser-grade TLS fingerprint without the bloat.

## Why curl-impersonate is slow

curl-impersonate patches libcurl + a TLS library (BoringSSL or NSS) to mimic browser TLS fingerprints. The perf problems:

1. **One-fd-per-transfer model** — libcurl's multi interface still does epoll + non-blocking sockets internally. Each connection is a state machine driven by poll readiness, not completion.
2. **Synchronous DNS** — c-ares helps but it's still callback-driven over epoll. DNS resolution blocks the pipeline start.
3. **Thread-per-connection scaling** — to saturate bandwidth you need many parallel transfers, each burning a curl_easy handle + TLS session + socket. Memory scales linearly.
4. **No batching** — each send/recv is a separate syscall. No SQE batching, no provided buffers.
5. **TLS in userspace but scheduled by kernel** — data arrives via epoll notification, gets copied to userspace, decrypted, then the app reads it. Two copies minimum.

## Architecture

```
                    ┌─────────────────────────────────┐
                    │         Crawl Scheduler          │
                    │  URL queue, dedup, rate limit    │
                    └──────────┬──────────────────────┘
                               │
                    ┌──────────▼──────────────────────┐
                    │       io_uring Reactor           │
                    │  Single ring, batched submit     │
                    │  Provided buffer rings for recv  │
                    └──┬─────────┬─────────┬──────────┘
                       │         │         │
                 ┌─────▼──┐ ┌───▼────┐ ┌──▼───────┐
                 │  DNS    │ │  TLS   │ │  HTTP    │
                 │ resolve │ │handshk │ │ parse    │
                 └─────────┘ └────────┘ └──────────┘
```

### DNS Resolution

- Raw UDP sendmsg/recvmsg via io_uring (`IORING_OP_SENDMSG` / `IORING_OP_RECVMSG`)
- Build DNS query packets directly (A/AAAA, ~40 bytes, no library needed)
- Pipeline: fire DNS for next batch while current batch is in TLS handshake
- Local cache with TTL respect. No /etc/resolv.conf parsing — configure resolver IP directly
- Optional: DNS-over-HTTPS for stealth (reuses the same TLS + HTTP stack)

### TCP + TLS

**CONNECT via io_uring** — `IORING_OP_CONNECT` for async TCP. Link SQE chains: `socket → connect → (TLS handshake)`.

**TLS without a library (the hard part):**

The core tension: browser fingerprint impersonation requires matching the exact ClientHello (extensions, cipher order, ALPN, key share groups, etc.). Options:

| Approach | Fingerprint control | Complexity | Performance |
|----------|-------------------|------------|-------------|
| Embed BoringSSL | Full (it's what Chrome uses) | Medium — statically link, call from freestanding | Good, but it owns the socket |
| Minimal TLS 1.3 implementation | Full | Very high — but TLS 1.3 is simpler than 1.2 | Best — no library overhead |
| rustls via FFI | Good | Medium | Good |
| Wrap OpenSSL BIO with custom transport | Full with patches | Medium-high | Okay — BIO callbacks add indirection |

**Recommended: BoringSSL with custom BIO.**

- BoringSSL is what curl-impersonate already uses for Chrome fingerprints
- Custom `BIO_METHOD` that reads/writes to io_uring-managed buffers instead of calling `read()`/`write()` on the fd
- The reactor owns the socket; BoringSSL just does crypto on buffers we hand it
- This decouples the TLS state machine from the I/O scheduler

**Fingerprint profiles** — struct that defines: cipher list, extension order, ALPN, supported groups, signature algorithms, key share, GREASE values, compression methods. Load at startup, stamp into ClientHello. Profiles for Chrome/Firefox/Safari.

### HTTP Engine

**HTTP/1.1 (minimum viable):**
- Request builder: method + headers + host. Static header templates with SIMD copy (reuse PREP_SQE pattern for header stamping)
- Response parser: status line + headers + body. Chunked transfer-encoding support
- Connection pooling: keep-alive with idle timeout, keyed by (host, port)
- Redirect following: 301/302/307/308 with configurable max depth

**HTTP/2 (stretch):**
- HPACK header compression
- Stream multiplexing over single connection — multiple URLs per TCP connection
- Server push handling (or ignore)
- This is where you'd see the biggest throughput gain over curl for crawling a single domain

### Provided Buffers for Recv

Reuse the existing buffer ring pattern. Group per connection state:
- Group 0: DNS response buffers (512B, small ring)
- Group 1: TLS record buffers (16KB — max TLS record size)
- Group 2: HTTP response body (configurable, 64KB default)

### Crawl Scheduler

- URL frontier: priority queue (breadth-first by default, configurable)
- Dedup: bloom filter or hash set on normalized URLs
- Rate limiting: per-domain token bucket. Politeness delay configurable
- Robots.txt: fetch + parse per domain, cache with TTL
- Max concurrent connections per domain (default 6, matching browser behavior)

## What makes this faster than curl-impersonate

| Dimension | curl-impersonate | This |
|-----------|-----------------|------|
| I/O model | epoll + non-blocking | io_uring completion, 1 syscall/batch |
| DNS | c-ares callbacks | Direct UDP via io_uring, pipelined |
| Recv buffers | malloc per read | Provided buffer rings, zero-alloc hot path |
| Batching | 1 syscall per I/O | N SQEs per submit |
| TLS I/O | Library owns socket | Reactor owns socket, TLS does crypto only |
| Scaling | Thread pool or async multi | Single-thread or shared-nothing multicore |
| Binary | ~5MB (libcurl + BoringSSL + deps) | Static binary, no runtime deps |

## Realistic scope

**Phase 1 — HTTP client over io_uring (no TLS)**
- CONNECT + SEND + RECV via reactor
- HTTP/1.1 request/response
- Connection pooling
- This alone is useful for internal/plaintext crawling and proves the I/O model

**Phase 2 — TLS integration**
- BoringSSL with custom BIO
- Chrome fingerprint profile
- HTTPS support

**Phase 3 — Crawler logic**
- URL scheduler, dedup, rate limiting
- Robots.txt
- Output: WARC or streaming to stdout

**Phase 4 — HTTP/2**
- HPACK, stream mux
- Single-connection-per-domain crawling

## Open questions

- **Certificate verification**: embed Mozilla CA bundle? Or trust-on-first-use for speed?
- **Cookie jar**: needed for crawling sites that require session cookies. Simple hash map keyed by domain?
- **JavaScript rendering**: out of scope. This is a network-level crawler, not a headless browser.
- **Compression**: sites return gzip/br/zstd. Decompress inline or post-process? Embedding zstd is ~30KB.
- **WARC output**: standard format for web archives. Worth supporting natively or leave to the caller?
