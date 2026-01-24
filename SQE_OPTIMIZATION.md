# SQE Array Fill Optimization (io_uring)

## Goal
Reduce per-submit overhead in `uring_submit()` by removing the O(n) loop that fills the SQ ring’s `array[]`, without changing observable semantics.

## Background (why the array exists)
The io_uring SQ ring is two distinct structures:
- `sqes[]`: the actual SQE structs (requests)
- `array[]`: a ring of **indices** pointing into `sqes[]`

The kernel consumes requests by walking `array[]` from `khead` to `ktail`. It does **not** scan `sqes[]` directly. That indirection is part of the ABI and enables ordering and skipping. Therefore, there is no “direct SQE insertion” path in the current ABI; the only way to tell the kernel which SQEs are ready is by advancing `ktail` and ensuring `array[]` contains the correct indices.

## Current behavior
In `uring_submit()` we currently do:
- compute `to_submit = sqe_tail - sqe_head`
- fill `array[ktail & mask] = i & mask` for each SQE index `i`
- advance `ktail` and publish it to the kernel

This is O(n) stores per submit. At high SQE rates this becomes a visible memory bandwidth + cache pressure cost.

## Key observation (identity mapping)
In this server, SQE allocation and submission are:
- single-producer (`IORING_SETUP_SINGLE_ISSUER`)
- strictly sequential (no reordering)
- always submit **contiguous** SQE indices `[sqe_head, sqe_tail)`

Under those constraints, we can maintain the invariant:

> **Invariant A:** `ktail == sqe_head` at the start of each `uring_submit()` call.

Proof sketch:
1. At init: `sqe_head = sqe_tail = 0`, `*ktail = 0` ⇒ invariant holds.
2. Each submit increments both `ktail` and `sqe_head` by the same `to_submit`.
3. No other code mutates `sqe_head` or `ktail`.
4. Therefore `ktail == sqe_head` at the next submit.

Given `ktail == sqe_head`, the loop assigns:

- `array[ktail & mask] = i & mask`
- with `i == ktail` as they advance together

So `array[slot] = slot` **every time**. That means `array[]` is just the identity mapping.

## Proposed optimization
Pre-fill `array[]` once with identity values, and remove the per-submit loop.

### Initialization (once)
After ring mapping and `ring_entries` are known:

```c
for (uint32_t i = 0; i < sq->ring_entries; i++) {
    sq->array[i] = i;
}
```

### Submit path (replace loop)
```c
uint32_t to_submit = sq->sqe_tail - sq->sqe_head;
if (!to_submit)
    return 0;

uint32_t ktail = *sq->ktail;
ktail += to_submit;

// Publish: kernel sees SQEs after this store
smp_store_release(sq->ktail, ktail);

sq->sqe_head = sq->sqe_tail;
return (int)to_submit;
```

No change to `uring_get_sqe()` or queue fullness logic.

## Correctness conditions (must hold)
This optimization is correct **iff** all are true:
- Single producer updates SQ ring (`IORING_SETUP_SINGLE_ISSUER`).
- SQEs are submitted in strict sequence, no reordering.
- You always submit a **contiguous** range `[sqe_head, sqe_tail)`.
- `sqe_head` and `ktail` are only updated in `uring_submit()`.

If any of these change (e.g., you skip SQEs or reorder), you must revert to filling `array[]` explicitly.

## Compatibility with kernel features
This remains valid with:
- `IORING_SETUP_SUBMIT_ALL`
- `IORING_SETUP_DEFER_TASKRUN`
- `IORING_SETUP_COOP_TASKRUN`
- `IORING_SETUP_SQPOLL` (still fine; kernel does not write `ktail`)

The ABI still requires `array[]`, but identity prefill satisfies it.

## Risks / failure modes
- If a future change submits SQEs out of order, the kernel will consume the wrong SQEs.
- If a second producer thread writes SQEs, identity mapping breaks.

Mitigation: guard the optimization with a compile-time flag and clearly document the invariants.

## Suggested integration plan
1. Pre-fill `sq->array` in `uring_init()` after `uring_mmap()`.
2. Replace the loop in `uring_submit()` with the O(1) tail increment path.
3. Add a comment above `uring_submit()` documenting the invariants.
4. Optionally provide a fallback path behind a macro, e.g. `URING_IDENTITY_ARRAY`.

## Why this is a worthwhile optimization
- Removes O(n) stores and a branchy loop from the hot path.
- Cuts cache pressure on the SQ ring memory.
- Keeps the ABI intact with zero behavioral change under the stated constraints.

If you want, I can implement this behind a macro so it’s easy to toggle and safe for future refactors.
