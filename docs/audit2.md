## Performance Audit Report: `event.c` + `uring.h`

### Executive Summary

The codebase is **well-optimized** for its purpose. Analysis of the assembly output (compiled with `-O3 -march=native` targeting Zen5/znver5) reveals good register utilization, proper inlining, and no register spills in the hot path. However, there are several opportunities for micro-optimizations.

---

### 1. Cache Line Layout Analysis

**Status: Mostly Well-Designed**

| Structure | Size | Cache Lines | Assessment |
|-----------|------|-------------|------------|
| `struct conn_state` | 1 byte | 64 connections/line | ⚠️ False sharing risk in multi-worker |
| `struct buf_ring` | 20 bytes | 1 | ✓ Good - hot fields grouped |
| `struct uring` | ~184 bytes | 3 | ✓ Acceptable |
| `struct io_uring_sqe` | 64 bytes | 1 | ✓ Perfect cache line alignment |
| `struct io_uring_cqe` | 16 bytes | 4 per line | ✓ Good density |

**Issue: `conn_state` Packing** (event.c:98-102)
```c
struct conn_state {  // Only 1 byte
    uint8_t closing : 1;
    uint8_t recv_active : 1;
    uint8_t reserved : 6;
};
```
64 file descriptors share one cache line. For single-threaded operation this is optimal (high cache density). For multi-worker with shared fd space, this causes false sharing.

---

### 2. Pointer Chasing Analysis

**Identified Chains:**

| Access Pattern | Dereferences | Frequency | Impact |
|----------------|--------------|-----------|--------|
| `ctx->br.br->bufs[idx]` | 2 | Per recv completion | Medium |
| `sq->khead` → `*khead` | 2 | Per SQE acquisition | Medium |
| `cq->cqes[idx]` | 1 | Per CQE | Low (prefetched) |
| `g_conns[fd]` | 1 | Per operation | Medium (random access) |

**Assembly Evidence** (event.c:555-558 → lines 845-861):
```asm
# CQE access - single indirection, prefetched
addq  %r13, %rax           # cqes + offset
prefetcht0  0(%r13,%rdx)   # prefetch next

# sq->khead access - loaded from stack each time
movq  -560(%rbp), %rcx     # load khead pointer from stack
movl  (%rcx), %r9d         # dereference to get head value
```

The `sq->khead` pointer is read from stack (`-560(%rbp)`) on every SQE acquisition. This is unavoidable since `ctx` is a stack variable, but the pointer-to-pointer indirection could be flattened.

---

### 3. SIMD/SWAR Opportunities

**Current SIMD Usage:**
- ✓ Compiler uses AVX-512 for `memset` operations (`vmovdqu8`)
- ✓ Initialization uses `vpmovzxdq`, `vpbroadcastq` for offset calculations

**Missed SIMD Opportunity: SQE Zero-Initialization**

Current approach (event.c:167-181, assembly lines 806-825):
```asm
# 8 individual 8-byte stores to zero SQE fields
movq  $0, 8(%rcx)    # off
movq  $0, 40(%rcx)   # buf_group area
movq  $0, 48(%rcx)   # addr3
movq  $0, 56(%rcx)   # __pad2
# Plus individual field writes...
```

**Potential Optimization:**
```c
// Use template SQE with pre-set common fields
static const struct io_uring_sqe sqe_template_send = {
    .opcode = IORING_OP_SEND,
    .flags = 0,
    // ... all zeros for other fields
};

// In prep_send_direct:
__m512i tmpl = _mm512_load_si512(&sqe_template_send);
_mm512_store_si512(sqe, tmpl);
sqe->fd = fd;
sqe->addr = (uint64_t)buf;
sqe->len = len;
sqe->user_data = encode_send(fd, buf_idx);
```

This replaces 8+ scalar stores with 1 SIMD store + 4 scalar overwrites.

**Estimated Impact:** Marginal (~2-4 cycles saved per SQE). Modern CPUs handle sequential stores efficiently with store buffer coalescing.

**SWAR Applicability:** **Not applicable.** This server:
- Uses static HTTP response (no parsing)
- No string processing in hot path
- No byte-level bit manipulation needed

---

### 4. Register Pressure Analysis

**Status: Excellent - No Spills**

Assembly analysis (lines 750-1250) shows:

| Register | Usage in Hot Path |
|----------|-------------------|
| `r8` | CQ head counter |
| `r10` | CQ tail (cached from ktail) |
| `r13` | `cqes` pointer (loop invariant) |
| `r14` | `cq_mask` (loop invariant) |
| `r12` | `br_tail_start` |
| `rbx` | `g_conns` base pointer |
| `rax,rcx,rdx,rsi,rdi,r9,r11` | Temporaries |
| `rbp` | Frame pointer (stack-relative addressing) |

**Verification:**
```bash
$ grep -c "(%rbp)" hot_path_section  # Stack accesses
15  # All are struct field accesses, not spills
```

All 16 GPRs are well-utilized. Stack accesses are for struct fields in `ctx` (which lives on stack), not register spills.

---

### 5. Switch Dispatch Efficiency

**Current Implementation** (event.c:565-584):
```asm
cmpb  $2, %cl      # OP_SEND?
je    .L54
jbe   .L249        # OP_ACCEPT (0) or OP_RECV (1)
cmpb  $3, %cl      # OP_CLOSE?
jne   .L59         # default (OP_SETSOCKOPT=4 or unknown)
```

This is a **compare chain**, not a jump table. For 5 cases, this is optimal:
- Most common ops (RECV=1, SEND=2) are checked first
- Branch predictor learns the pattern quickly
- Jump table overhead not worthwhile for <8 cases

---

### 6. Specific Bottleneck Findings

#### 6.1 Repeated `sq->khead` Dereference

Each `uring_get_sqe()` call loads `sq->khead` from stack then dereferences:
```asm
movq  -560(%rbp), %rcx   # Load khead pointer
movl  (%rcx), %r9d       # Load actual head value
```

In a burst of SQE acquisitions (accept → setsockopt → recv), this happens 3 times per connection.

**Mitigation:** Cache `khead` value at start of CQE processing batch:
```c
uint32_t sq_head = *sq->khead;  // Read once
// Use cached value for available space check
```

However, the kernel may consume SQEs between checks. The current conservative approach is correct for safety.

#### 6.2 `buf_ring` Field Reloads

Each buffer recycle reloads `br->tail`, `br->mask`, `br->br`, `br->buf_base` from stack:
```asm
movzwl  -360(%rbp), %edi   # br->tail
movzwl  -358(%rbp), %ecx   # br->mask
movq    -376(%rbp), %rcx   # br->br
addq    -368(%rbp), %rsi   # br->buf_base
```

**Mitigation:** If multiple buffers are recycled per iteration, a local copy would help:
```c
// Cache at start of CQE batch
uint16_t local_tail = br->tail;
uint16_t local_mask = br->mask;
struct io_uring_buf_ring *local_br = br->br;
uint8_t *local_base = br->buf_base;
// Use locals in loop
br->tail = local_tail;  // Write back once
```

**Impact:** Low - stack access is L1-hot, 1-cycle latency.

---

### 7. Summary of Recommendations

| Priority | Issue | Fix | Expected Impact |
|----------|-------|-----|-----------------|
| P1 | Prefetch `g_conns[fd]` instead of CQE | See PERFORMANCE_AUDIT.md | Reduced cache misses |
| P2 | SQE template with SIMD copy | AVX-512 store + scalar overwrites | ~2-4 cycles/SQE |
| P3 | Cache buf_ring fields locally | Local variables in CQE loop | ~1-2 cycles/recycle |
| P4 | `conn_state` padding (multi-worker) | Pad to 8 bytes | Eliminates false sharing |
| - | Switch dispatch | No change needed | Already optimal |
| - | Register pressure | No change needed | Zero spills |

---

### 8. Things Done Correctly

The existing PERFORMANCE_AUDIT.md already documents many optimizations. The codebase demonstrates:

- ✓ O(1) SQ submit via identity mapping
- ✓ Conditional `buf_ring_sync()` (only when buffers recycled)
- ✓ `IOSQE_CQE_SKIP_SUCCESS` for fire-and-forget ops
- ✓ Pre-shifted operation codes (`OP_RECV_SHIFTED`)
- ✓ Shift instead of multiply for buffer address calculation
- ✓ x86-TSO optimized memory barriers
- ✓ CQE prefetching
- ✓ All hot path functions inlined
- ✓ Good branch hint placement (`likely`/`unlikely`)

The server is already highly optimized. Remaining improvements are micro-optimizations with diminishing returns.

---

### Conclusion

The codebase is **production-quality** from a performance perspective. The assembly analysis confirms:

1. **No register spills** in the hot path
2. **Effective inlining** - all handler functions merged into `main`
3. **Good SIMD usage** for initialization (compiler-generated AVX-512)
4. **Efficient switch dispatch** via compare chain

The main actionable item is the **connection state prefetch** (already noted in existing audit docs). The SIMD template optimization for SQE preparation is theoretically sound but offers marginal gains since modern x86 store buffers coalesce sequential stores efficiently.

SWAR techniques are **not applicable** here - there's no byte-level string processing in the hot path (static HTTP response, no parsing).
