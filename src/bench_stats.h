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
