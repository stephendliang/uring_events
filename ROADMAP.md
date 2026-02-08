# Roadmap

Current state: single-threaded io_uring HTTP server, freestanding 26KB binary,
static "OK" response. See CLAUDE.md for architecture.

## Planned

### Rate Limiting
- Per-client connection/request tracking
- Reject excessive clients before buffer allocation (early in accept path)
- 429 response + immediate close for over-limit clients
- Design TBD — no implementation yet

## Future

### Multi-Core Scaling
- Fork-per-core workers, each with own io_uring + buffer rings + connection state
- Shared-nothing: no cross-core communication in hot path
- SO_REUSEPORT already set; SO_INCOMING_CPU already set; CPU pinning works
- Requires: conn_state padding (false sharing at 1 byte), per-worker listen fd
- Not next — current single-threaded perf is the focus

## Maybe

- **TLS** — no design, no timeline. kTLS or userspace, undecided.

## Non-Goals

- **QUIC / UDP** — fundamentally different batching model
- **HTTP parsing** — static response is intentional (benchmark harness)
- **Framework / library** — application logic is compiled in
- **SQPOLL** — kernel polling threads burn CPU, fight for cache
