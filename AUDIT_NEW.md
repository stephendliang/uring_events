 Findings (ordered by severity)

  1. High: zc release is currently broken and cannot link without libc.
     I reproduced make zc failing with unresolved memset. This directly contradicts “glibc-free release builds” for the zc release
     path.
     Key sites that trigger compiler-emitted memset calls under -DNOLIBC -DENABLE_ZC are src/event.c:628, src/uring.h:454, and src/
     uring.h:513.
     Related build target: Makefile:30.
  2. High: make release can silently keep a glibc-linked debug binary.
     Repro: make clean && make debug && make release results in “Nothing to be done for 'release'”, and the output stays dynamically
     linked to libc.
     Root cause: all modes write the same output file (event) with no config-specific object/output separation: Makefile:21,
     Makefile:24, Makefile:26, Makefile:29.
     This makes release-mode guarantees unreliable unless users remember make clean.
  3. Medium: possible out-of-bounds write pattern from mem_zero_aligned usage.
     mem_zero_aligned is documented as requiring 64-byte-multiple lengths (src/util.h:8) and stores in 64-byte steps (src/util.h:25,
     src/util.h:29).
     But src/uring.h:626 uses it on probe_size, which is 2064 bytes (mod 64 = 16). On AVX2/AVX-512 paths this writes past logical end.
     It happens to be cushioned by page-rounded mmap today, but it is still unsafe/fragile API misuse.
  4. Medium: mem_copy_small has UB for unaligned pointers and likely throughput loss.
     src/util.h:257 advertises arbitrary unaligned copy, but src/util.h:261 casts to u64 * and dereferences directly, which is
     undefined for misaligned addresses (UBSan flags this).
     Hot-path call is src/event.c:383.
     I also measured it slower than libc memcpy in a quick local microbench (~0.73x–0.91x for 512B–4KB copies), so this can be a
     performance regression in ZC path.
  5. Medium: security hardening regression from static non-PIE output.
     Makefile:9 enforces -static with no PIE flags; resulting binary is EXEC (fixed base), not PIE.
     If exploitation resistance matters, this is a real tradeoff (ASLR effectiveness drops).
  6. Low: signal handler installation result is ignored in nolibc mode.
     k_sigaction return values are not checked at src/event.c:634 and src/event.c:635.
     If either fails, graceful shutdown on SIGINT/SIGTERM may silently stop working.
