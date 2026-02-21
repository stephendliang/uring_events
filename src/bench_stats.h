#pragma once
// bench_stats.h — Timing and statistics for the benchmark.
// clock_gettime(CLOCK_MONOTONIC) via raw syscall, shell sort, percentiles.

#include "bench_syscalls.h"
#include <linux/time_types.h>  // struct __kernel_timespec

// Returns current monotonic time in nanoseconds.
// ~20ns overhead — negligible vs microsecond+ I/O latency.
static inline u64 bench_now_ns(void) {
    struct __kernel_timespec ts;
    sys_clock_gettime(1 /* CLOCK_MONOTONIC */, &ts);
    return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

// In-place shell sort for u64 array.
// Shell sort: O(n^1.25) average, no extra memory, good enough for
// sorting latency arrays up to ~10M entries on the cold path.
static inline void bench_sort_u64(u64 *arr, u32 n) {
    // Ciura gap sequence — empirically optimal for shell sort
    static const u32 gaps[] = {
        701, 301, 132, 57, 23, 10, 4, 1
    };

    for (u32 gi = 0; gi < sizeof(gaps) / sizeof(gaps[0]); gi++) {
        u32 gap = gaps[gi];
        if (gap >= n) continue;

        for (u32 i = gap; i < n; i++) {
            u64 tmp = arr[i];
            u32 j = i;
            while (j >= gap && arr[j - gap] > tmp) {
                arr[j] = arr[j - gap];
                j -= gap;
            }
            arr[j] = tmp;
        }
    }
}

// Extract percentile from sorted array. pct_x10 = percentile * 10
// (e.g., 500 = p50, 990 = p99, 999 = p99.9).
static inline u64 bench_percentile(const u64 *sorted, u32 n, u32 pct_x10) {
    if (n == 0) return 0;
    u64 idx = ((u64)pct_x10 * (n - 1)) / 1000;
    return sorted[idx];
}

// --- Confidence interval infrastructure ---

// Integer square root via Newton's method.
static inline u64 bench_isqrt64(u64 n) {
    if (n == 0) return 0;
    u64 r = 1;
    while (r * r <= n && r < (1ULL << 32)) r <<= 1;
    r >>= 1;
    for (int i = 0; i < 64; i++) {
        u64 nr = (r + n / r) / 2;
        if (nr >= r) break;
        r = nr;
    }
    return r;
}

struct bench_ci {
    u64 mean;
    u64 ci_half;      // 95% CI half-width (same unit as input)
    u32 ci_pct_x10;   // CI half-width as permille of mean (e.g., 35 = 3.5%)
};

// t-distribution critical values x1000 for 95% CI (two-tailed).
// Indexed by df = n-1, for n = 3..30.
static const u32 _t_crit[] = {
    4303, 3182, 2776, 2571, 2447, 2365, 2306, 2262,  // df 2-9
    2228, 2201, 2179, 2160, 2145, 2131, 2120, 2110,  // df 10-17
    2101, 2093, 2086, 2080, 2074, 2069, 2064, 2060,  // df 18-25
    2056, 2052, 2048, 2045,                           // df 26-29
};

// sqrt(n) x 1000 for n = 3..30.
static const u32 _sqrt_n[] = {
    1732, 2000, 2236, 2449, 2646, 2828, 3000, 3162,  // n 3-10
    3317, 3464, 3606, 3742, 3873, 4000, 4123, 4243,  // n 11-18
    4359, 4472, 4583, 4690, 4796, 4899, 5000, 5099,  // n 19-26
    5196, 5292, 5385, 5477,                           // n 27-30
};

// Compute 95% CI for an array of u64 values.
// Requires 3 <= n <= 30. Outside that range, ci_half = 0.
static inline void bench_compute_ci(const u64 *values, u32 n,
                                     struct bench_ci *out) {
    u64 sum = 0;
    for (u32 i = 0; i < n; i++) sum += values[i];
    out->mean = sum / n;

    if (n < 3 || n > 30) {
        out->ci_half = 0;
        out->ci_pct_x10 = 0;
        return;
    }

    // Sample variance (Bessel's correction)
    u64 sum_sq = 0;
    for (u32 i = 0; i < n; i++) {
        i64 d = (i64)(values[i] - out->mean);
        sum_sq += (u64)(d * d);
    }
    u64 variance = sum_sq / (n - 1);
    u64 stddev = bench_isqrt64(variance);

    // CI_half = t * stddev / sqrt(n)
    u32 t_x1000 = _t_crit[n - 3];
    u32 sqrt_n_x1000 = _sqrt_n[n - 3];
    out->ci_half = (u64)t_x1000 * stddev / sqrt_n_x1000;

    out->ci_pct_x10 = (out->mean > 0)
        ? (u32)(out->ci_half * 1000 / out->mean) : 0;
}
