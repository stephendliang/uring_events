#pragma once
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

// 5-field variant for file I/O: patches fd, off, addr, len, user_data
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
