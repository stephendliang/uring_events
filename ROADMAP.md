# Roadmap

Current state: single-threaded io_uring HTTP server, freestanding 26KB binary,
static "OK" response. See [prompt.md](prompt.md) for architecture.

## Done

### Multi-Core Scaling (2026-02-21)
- Raw `clone()` syscall 56 — 15-instruction asm trampoline, no libc
- Per-worker: listen socket, io_uring, fixed files, buffer rings, connection state
- Shared-nothing: zero cross-thread communication, no CLONE_FILES
- Stride-2 CPU assignment skips HT siblings (one worker per physical core)
- Futex-based join (CLONE_CHILD_CLEARTID)
- `#ifdef MULTICORE` — default build unchanged
- See [docs/2026-02-21-multicore.md](docs/2026-02-21-multicore.md)

## Planned

### Rate Limiting
- Per-client connection/request tracking
- Reject excessive clients before buffer allocation (early in accept path)
- 429 response + immediate close for over-limit clients
- Design TBD — no implementation yet

## Maybe

- **TLS** — no design, no timeline. kTLS or userspace, undecided.

## Non-Goals

- **QUIC / UDP** — fundamentally different batching model
- **HTTP parsing** — static response is intentional (benchmark harness)
- **Framework / library** — application logic is compiled in
- **SQPOLL** — kernel polling threads burn CPU, fight for cache
