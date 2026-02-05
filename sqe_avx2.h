#pragma once
#include <immintrin.h>

#define PREP_SQE(sqe, tmpl, fd_val, ud_val) do {                                      \
    __m256i lo = _mm256_load_si256((const __m256i *)&(tmpl));                          \
    __m256i hi = _mm256_load_si256((const __m256i *)&(tmpl) + 1);                     \
    lo = _mm256_blend_epi32(lo, _mm256_set1_epi32((fd_val)), 1 << 1);                \
    hi = _mm256_blend_epi32(hi, _mm256_set1_epi64x((long long)(ud_val)), 0x03);      \
    _mm256_store_si256((__m256i *)(sqe), lo);                                          \
    _mm256_store_si256((__m256i *)(sqe) + 1, hi);                                     \
} while (0)
