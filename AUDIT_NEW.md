 Findings (ordered by severity)

  1. High: make release can silently keep a glibc-linked debug binary.
     Repro: make clean && make debug && make release results in "Nothing to be done for 'release'", and the output stays dynamically
     linked to libc.
     Root cause: all modes write the same output file (event) with no config-specific object/output separation: Makefile:21,
     Makefile:24, Makefile:26, Makefile:29.
     This makes release-mode guarantees unreliable unless users remember make clean.
  2. Medium: security hardening regression from static non-PIE output.
     Makefile:9 enforces -static with no PIE flags; resulting binary is EXEC (fixed base), not PIE.
     If exploitation resistance matters, this is a real tradeoff (ASLR effectiveness drops).
