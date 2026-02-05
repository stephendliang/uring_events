#pragma once
#include <immintrin.h>

#define PREP_SQE(sqe, tmpl, fd_val, ud_val) do {                       \
    __m512i zmm = _mm512_load_si512((const __m512i *)&(tmpl));         \
    zmm = _mm512_mask_set1_epi32(zmm, 1U << 1, (fd_val));             \
    zmm = _mm512_mask_set1_epi64(zmm, 1U << 4, (long long)(ud_val));  \
    _mm512_store_si512((__m512i *)(sqe), zmm);                         \
} while (0)
