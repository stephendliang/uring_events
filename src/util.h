#pragma once

#include "core.h"

// SIMD memory primitives — 3-tier dispatch (AVX-512 / AVX2 / scalar).
//
// All "aligned" / "nt" variants require:
//   - dst (and src) 64-byte aligned
//   - n is a multiple of 64 bytes
//
// Non-temporal (NT) variants bypass cache — use for large buffers that
// won't be read soon by userspace (e.g., passed to kernel then munmap'd).

#if defined(__AVX512F__)
// AVX-512: one 64-byte store per cache line
#define _MM_MALLOC_H_INCLUDED
#include <immintrin.h>

#pragma GCC push_options
#pragma GCC optimize("no-tree-loop-distribute-patterns")

static inline void mem_zero_aligned(void *dst, u64 n) {
    __m512i zero = _mm512_setzero_si512();
    u8 *p = (u8 *)dst;
    u8 *end = p + n;
    while (p < end) {
        _mm512_store_si512((__m512i *)p, zero);
        p += 64;
    }
}

static inline void mem_zero_nt(void *dst, u64 n) {
    __m512i zero = _mm512_setzero_si512();
    u8 *p = (u8 *)dst;
    u8 *end = p + n;
    while (p < end) {
        _mm512_stream_si512((__m512i *)p, zero);
        p += 64;
    }
    _mm_sfence();
}

static inline void mem_fill_nt(void *dst, u8 val, u64 n) {
    __m512i v = _mm512_set1_epi8((char)val);
    u8 *p = (u8 *)dst;
    u8 *end = p + n;
    while (p < end) {
        _mm512_stream_si512((__m512i *)p, v);
        p += 64;
    }
    _mm_sfence();
}

static inline void mem_copy_aligned(void *restrict dst,
                                     const void *restrict src, u64 n) {
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    const u8 *end = s + n;
    while (s < end) {
        __m512i v = _mm512_load_si512((const __m512i *)s);
        _mm512_store_si512((__m512i *)d, v);
        s += 64;
        d += 64;
    }
}

static inline void mem_copy_nt(void *restrict dst,
                                const void *restrict src, u64 n) {
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    const u8 *end = s + n;
    while (s < end) {
        __m512i v = _mm512_load_si512((const __m512i *)s);
        _mm512_stream_si512((__m512i *)d, v);
        s += 64;
        d += 64;
    }
    _mm_sfence();
}

static inline void mem_zero_cacheline(void *dst) {
    _mm512_store_si512((__m512i *)dst, _mm512_setzero_si512());
}

static inline void mem_iota_u32(u32 *dst, u32 n) {
    __m512i base = _mm512_setr_epi32(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    __m512i step = _mm512_set1_epi32(16);
    u32 *end = dst + (n & ~15U);  // Round down to multiple of 16
    u32 val = 0;
    while (dst < end) {
        _mm512_store_si512((__m512i *)dst, base);
        base = _mm512_add_epi32(base, step);
        dst += 16;
        val += 16;
    }
    // Scalar remainder
    while (val < n) {
        *dst++ = val++;
    }
}

#pragma GCC pop_options

#elif defined(__AVX2__)
// AVX2: two 32-byte stores per cache line
#define _MM_MALLOC_H_INCLUDED
#include <immintrin.h>

#pragma GCC push_options
#pragma GCC optimize("no-tree-loop-distribute-patterns")

static inline void mem_zero_aligned(void *dst, u64 n) {
    __m256i zero = _mm256_setzero_si256();
    u8 *p = (u8 *)dst;
    u8 *end = p + n;
    while (p < end) {
        _mm256_store_si256((__m256i *)p, zero);
        _mm256_store_si256((__m256i *)(p + 32), zero);
        p += 64;
    }
}

static inline void mem_zero_nt(void *dst, u64 n) {
    __m256i zero = _mm256_setzero_si256();
    u8 *p = (u8 *)dst;
    u8 *end = p + n;
    while (p < end) {
        _mm256_stream_si256((__m256i *)p, zero);
        _mm256_stream_si256((__m256i *)(p + 32), zero);
        p += 64;
    }
    _mm_sfence();
}

static inline void mem_fill_nt(void *dst, u8 val, u64 n) {
    __m256i v = _mm256_set1_epi8((char)val);
    u8 *p = (u8 *)dst;
    u8 *end = p + n;
    while (p < end) {
        _mm256_stream_si256((__m256i *)p, v);
        _mm256_stream_si256((__m256i *)(p + 32), v);
        p += 64;
    }
    _mm_sfence();
}

static inline void mem_copy_aligned(void *restrict dst,
                                     const void *restrict src, u64 n) {
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    const u8 *end = s + n;
    while (s < end) {
        __m256i lo = _mm256_load_si256((const __m256i *)s);
        __m256i hi = _mm256_load_si256((const __m256i *)(s + 32));
        _mm256_store_si256((__m256i *)d, lo);
        _mm256_store_si256((__m256i *)(d + 32), hi);
        s += 64;
        d += 64;
    }
}

static inline void mem_copy_nt(void *restrict dst,
                                const void *restrict src, u64 n) {
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    const u8 *end = s + n;
    while (s < end) {
        __m256i lo = _mm256_load_si256((const __m256i *)s);
        __m256i hi = _mm256_load_si256((const __m256i *)(s + 32));
        _mm256_stream_si256((__m256i *)d, lo);
        _mm256_stream_si256((__m256i *)(d + 32), hi);
        s += 64;
        d += 64;
    }
    _mm_sfence();
}

static inline void mem_zero_cacheline(void *dst) {
    __m256i zero = _mm256_setzero_si256();
    _mm256_store_si256((__m256i *)dst, zero);
    _mm256_store_si256((__m256i *)((u8 *)dst + 32), zero);
}

static inline void mem_iota_u32(u32 *dst, u32 n) {
    __m256i base = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
    __m256i step = _mm256_set1_epi32(8);
    u32 *end = dst + (n & ~7U);  // Round down to multiple of 8
    u32 val = 0;
    while (dst < end) {
        _mm256_store_si256((__m256i *)dst, base);
        base = _mm256_add_epi32(base, step);
        dst += 8;
        val += 8;
    }
    // Scalar remainder
    while (val < n) {
        *dst++ = val++;
    }
}

#pragma GCC pop_options

#else
// Scalar: explicit loops — __builtin_memset/memcpy emit glibc calls
// for sizes > ~512B. The pragma prevents GCC from converting loops back.

#pragma GCC push_options
#pragma GCC optimize("no-tree-loop-distribute-patterns")

static inline void mem_zero_aligned(void *dst, u64 n) {
    u8 *p = (u8 *)dst;
    u8 *end = p + n;
    while (p < end) { *(u64 *)p = 0; p += 8; }
}

static inline void mem_zero_nt(void *dst, u64 n) {
    u8 *p = (u8 *)dst;
    u8 *end = p + n;
    while (p < end) { *(u64 *)p = 0; p += 8; }
}

static inline void mem_fill_nt(void *dst, u8 val, u64 n) {
    u64 fill = val * 0x0101010101010101ULL;
    u8 *p = (u8 *)dst;
    u8 *end = p + n;
    while (p < end) { *(u64 *)p = fill; p += 8; }
}

static inline void mem_copy_aligned(void *restrict dst,
                                     const void *restrict src, u64 n) {
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    const u8 *end = s + n;
    while (s < end) { *(u64 *)d = *(const u64 *)s; s += 8; d += 8; }
}

static inline void mem_copy_nt(void *restrict dst,
                                const void *restrict src, u64 n) {
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    const u8 *end = s + n;
    while (s < end) { *(u64 *)d = *(const u64 *)s; s += 8; d += 8; }
}

// 64B constant — GCC always inlines this as store sequence
static inline void mem_zero_cacheline(void *dst) {
    __builtin_memset(dst, 0, 64);
}

static inline void mem_iota_u32(u32 *dst, u32 n) {
    for (u32 i = 0; i < n; i++)
        dst[i] = i;
}

#pragma GCC pop_options

#endif

// Unaligned-safe u64 — generates identical mov on x86-64
typedef u64 __attribute__((aligned(1))) u64_ua;

// Byte-granular copy for arbitrary sizes (e.g., ZC send path).
// Not aligned, not SIMD — for small copies only (<4KB).
#pragma GCC push_options
#pragma GCC optimize("no-tree-loop-distribute-patterns")
static inline void mem_copy_small(void *restrict dst,
                                   const void *restrict src, u32 n) {
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    while (n >= 8) { *(u64_ua *)d = *(const u64_ua *)s; d += 8; s += 8; n -= 8; }
    while (n--) *d++ = *s++;
}
#pragma GCC pop_options
