#pragma once
#define _MM_MALLOC_H_INCLUDED
#include <immintrin.h>

#define PREP_SQE(sqe, tmpl, fd_val, ud_val) do {                       \
    __m512i zmm = _mm512_load_si512((const __m512i *)&(tmpl));         \
    zmm = _mm512_mask_set1_epi32(zmm, 1U << 1, (fd_val));             \
    zmm = _mm512_mask_set1_epi64(zmm, 1U << 4, (long long)(ud_val));  \
    _mm512_store_si512((__m512i *)(sqe), zmm);                         \
} while (0)

// 5-field variant for file I/O: patches fd, off, addr, len, user_data
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
