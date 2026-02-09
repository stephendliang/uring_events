Findings (severity-ordered)

1. High Regression against repo test contract: the commit makes ./scripts/test.sh fail.
- src/uring.c:97 removed IORING_SETUP_COOP_TASKRUN.
- scripts/test.sh:111 and scripts/test.sh:122 still require that flag and fail Phase 1 with a fatal error.
- Net: this commit is red against the project’s own validation gate unless test/policy is updated in the same change.

2. Medium Portability regression risk on older kernel headers.
- New symbols are used without compatibility guards: src/uring.c:131, src/uring.c:144, src/uring.c:146, src/uring.h:279.
- The file already uses #ifndef shims for other newer io_uring constants (src/uring.h:22), so this is inconsistent and can break builds on
  older header sets even though runtime fallback logic exists.

3. Low Lifecycle risk if process/thread persists and server_run() is reused.
- Ring-fd registration added at src/uring.c:131.
- No IORING_UNREGISTER_RING_FDS path; only close(ctx.ring.ring_fd) at src/event.c:709.
- Per io_uring_register(2), registered ring-fd slots may persist for a living task; repeated init/teardown in one process can eventually
    exhaust slots.

What looked good
- IOSQE_CQE_SKIP_SUCCESS on close plus closing gating is coherent in this code path (src/event.c:104, src/event.c:291, src/event.c:417).
- Dead-store removal and hot-cacheline padding correction in src/event.c are good optimizations.
- IORING_REGISTER_FILES2 sparse-first with fallback in src/uring.c is a sensible startup optimization.

