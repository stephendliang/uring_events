#pragma once

// PREP_SQE: 64-byte template copy + patch fd and user_data
// PREP_SQE_FILE: 5-field variant for file I/O (fd, off, addr, len, user_data)
// Compile-time dispatch: AVX-512 > AVX2 > scalar

#if defined(__AVX512F__)

#define _MM_MALLOC_H_INCLUDED
#include <immintrin.h>

#define PREP_SQE(sqe, tmpl, fd_val, ud_val) do {                       \
    __m512i zmm = _mm512_load_si512((const __m512i *)&(tmpl));         \
    zmm = _mm512_mask_set1_epi32(zmm, 1U << 1, (fd_val));             \
    zmm = _mm512_mask_set1_epi64(zmm, 1U << 4, (long long)(ud_val));  \
    _mm512_store_si512((__m512i *)(sqe), zmm);                         \
} while (0)

// SQE layout: dword 1=fd, qword 1=off, qword 2=addr, dword 6=len, qword 4=ud
#define PREP_SQE_FILE(sqe, tmpl, fd_val, off_val, addr_val, len_val, ud_val) do { \
    __m512i zmm = _mm512_load_si512((const __m512i *)&(tmpl));                     \
    zmm = _mm512_mask_set1_epi32(zmm, 1U << 1, (int)(fd_val));                    \
    zmm = _mm512_mask_set1_epi64(zmm, 1U << 1, (long long)(off_val));             \
    zmm = _mm512_mask_set1_epi64(zmm, 1U << 2, (long long)(addr_val));            \
    zmm = _mm512_mask_set1_epi32(zmm, 1U << 6, (int)(len_val));                   \
    zmm = _mm512_mask_set1_epi64(zmm, 1U << 4, (long long)(ud_val));              \
    _mm512_store_si512((__m512i *)(sqe), zmm);                                     \
} while (0)

#elif defined(__AVX2__)

#define _MM_MALLOC_H_INCLUDED
#include <immintrin.h>

#define PREP_SQE(sqe, tmpl, fd_val, ud_val) do {                                      \
    __m256i lo = _mm256_load_si256((const __m256i *)&(tmpl));                          \
    __m256i hi = _mm256_load_si256((const __m256i *)&(tmpl) + 1);                     \
    lo = _mm256_blend_epi32(lo, _mm256_set1_epi32((fd_val)), 1 << 1);                \
    hi = _mm256_blend_epi32(hi, _mm256_set1_epi64x((long long)(ud_val)), 0x03);      \
    _mm256_store_si256((__m256i *)(sqe), lo);                                          \
    _mm256_store_si256((__m256i *)(sqe) + 1, hi);                                     \
} while (0)

// Lower 256 bits: blend fd(dw1), off(qw1), addr(qw2), len(dw6) over template
// Upper 256 bits: blend user_data(qw4) over template
#define PREP_SQE_FILE(sqe, tmpl, fd_val, off_val, addr_val, len_val, ud_val) do {     \
    __m256i lo = _mm256_load_si256((const __m256i *)&(tmpl));                          \
    lo = _mm256_blend_epi32(lo, _mm256_set1_epi32((int)(fd_val)), 1 << 1);            \
    lo = _mm256_blend_epi32(lo,                                                        \
             _mm256_set1_epi64x((long long)(off_val)), (1 << 2) | (1 << 3));          \
    lo = _mm256_blend_epi32(lo,                                                        \
             _mm256_set1_epi64x((long long)(addr_val)), (1 << 4) | (1 << 5));         \
    lo = _mm256_blend_epi32(lo, _mm256_set1_epi32((int)(len_val)), 1 << 6);           \
    __m256i hi = _mm256_load_si256((const __m256i *)&(tmpl) + 1);                      \
    hi = _mm256_blend_epi32(hi, _mm256_set1_epi64x((long long)(ud_val)), 0x03);       \
    _mm256_store_si256((__m256i *)(sqe), lo);                                          \
    _mm256_store_si256((__m256i *)(sqe) + 1, hi);                                     \
} while (0)

#else

#define PREP_SQE(sqe, tmpl, fd_val, ud_val) do { \
    *(sqe) = (tmpl);                              \
    (sqe)->fd = (fd_val);                         \
    (sqe)->user_data = (ud_val);                  \
} while (0)

// Struct copy + patch fd, off, addr, len, user_data
#define PREP_SQE_FILE(sqe, tmpl, fd_val, off_val, addr_val, len_val, ud_val) do { \
    *(sqe) = (tmpl);                                                               \
    (sqe)->fd        = (fd_val);                                                   \
    (sqe)->off       = (off_val);                                                  \
    (sqe)->addr      = (addr_val);                                                 \
    (sqe)->len       = (len_val);                                                  \
    (sqe)->user_data = (ud_val);                                                   \
} while (0)

#endif
