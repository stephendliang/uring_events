# Performance Audit

Audit of io_uring server optimizations. Findings below are severity-ordered.

## Resolved

### 1. [was High] COOP_TASKRUN removal vs test contract

**Original finding:** Removing `IORING_SETUP_COOP_TASKRUN` from `uring.c` would make `scripts/test.sh` fail at Phase 1.

**Resolution:** `DEFER_TASKRUN` subsumes `COOP_TASKRUN` — the kernel ignores COOP when DEFER is set (see `uring.c` comment). `test.sh` checks for `SUBMIT_ALL`, `SINGLE_ISSUER`, and `DEFER_TASKRUN` only; it does not check for `COOP_TASKRUN`. No regression.

### 2. [was Medium] Missing kernel header compat guards

**Original finding:** New io_uring symbols used without `#ifndef` guards, inconsistent with existing shims.

**Resolution:** `uring.h` now provides `#ifndef` guards for all newer symbols: `IORING_SETUP_NO_SQARRAY`, `IORING_FILE_INDEX_ALLOC`, `IORING_OP_SEND_ZC`, `IORING_RECVSEND_BUNDLE`, `IORING_CQE_F_NOTIF`, `IORING_REGISTER_RING_FDS`, `IORING_UNREGISTER_RING_FDS`, `IORING_ENTER_REGISTERED_RING`, `IORING_REGISTER_FILES2`, `IORING_RSRC_REGISTER_SPARSE`, `SOCKET_URING_OP_SETSOCKOPT`, `IORING_OP_URING_CMD`.

### 3. [was Low] No ring fd unregister path

**Original finding:** Ring fd registered at startup but no `IORING_UNREGISTER_RING_FDS` path; only `close(ring_fd)`.

**Resolution:** `event.c` server_run cleanup now checks `ctx.ring.registered_index >= 0` and calls `IORING_UNREGISTER_RING_FDS` before closing the ring fd.

## What Looked Good

- `IOSQE_CQE_SKIP_SUCCESS` on close plus `closing` gating is coherent.
- Dead-store removal and hot-cacheline padding correction in `event.c`.
- `IORING_REGISTER_FILES2` sparse-first with fallback is a sensible startup optimization.
