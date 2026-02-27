// bench_conn.c — Idle-tracking strategy microbenchmark at 1M connections.
//
// Compares 3 strategies for tracking connection idleness:
//   sieve    CLOCK algorithm with bit-packed accessed array
//   linear   Timestamp + O(N) sequential scan
//   wheel    Timing wheel with RDTSC-quantized u8 epochs
//
// Previous benchmarks proved: (1) layout (SoA/AoS/packed) doesn't matter,
// (2) LRU linked-list pointer-chasing is the real cost and is dominated
// by all three alternatives at every connection count.
//
// Usage: bench-conn [cpu]

#define NOLIBC_MAIN
#include "core.h"

#define IS_MMAP_ERR(p) ((unsigned long)(p) >= (unsigned long)-4095UL)

// ── Configuration ──────────────────────────────────────────────

#define MAX_CONN        1048576   // 1M
#define WARMUP_BATCHES  2000
#define MEASURE_BATCHES 200000
#define BATCH_SIZE      128

#define F_CLOSING     0x01
#define F_RECV_ACTIVE 0x02
#define F_CANCEL_SENT 0x04

// ── PRNG (xoshiro256**) ────────────────────────────────────────

struct rng { u64 s[4]; };

static inline u64 rng_next(struct rng *r) {
    u64 *s = r->s;
    u64 r1 = s[1] * 5;
    u64 result = ((r1 << 7) | (r1 >> 57)) * 9;
    u64 t = s[1] << 17;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
    s[2] ^= t; s[3] = (s[3] << 45) | (s[3] >> 19);
    return result;
}

static void rng_init(struct rng *r, u64 seed) {
    r->s[0] = seed ^ 0xdeadbeefcafe1234ULL;
    r->s[1] = seed ^ 0x0123456789abcdefULL;
    r->s[2] = seed ^ 0xfedcba9876543210ULL;
    r->s[3] = seed ^ 0x1234567890abcdefULL;
    for (int i = 0; i < 16; i++) rng_next(r);
}

// ── Strategy 1: Sieve (CLOCK with bit array) ───────────────────

struct sieve {
    u8  *flags;
    u8  *accessed;    // bit-packed: accessed[fd >> 3] & (1 << (fd & 7))
    u32  max_fd;      // highest active fd (sweep scans up to this)
};

#define SIEVE_SIZE (MAX_CONN + (MAX_CONN / 8))  // ~1.125MB at 1M

static void sieve_setup(struct sieve *s, void *mem, u32 n_active) {
    s->flags    = (u8 *)mem;
    s->accessed = (u8 *)mem + MAX_CONN;
    s->max_fd   = n_active;

    for (u32 i = 1; i <= n_active; i++) {
        s->flags[i] = F_RECV_ACTIVE;
        s->accessed[i >> 3] |= (u8)(1 << (i & 7));
    }
}

static inline void sieve_touch(struct sieve *s, u32 fd, u64 ts) {
    (void)ts;
    u8 f = s->flags[fd];
    if (f & F_CLOSING) return;
    s->accessed[fd >> 3] |= (u8)(1 << (fd & 7));
}

// Byte-at-a-time sweep: processes 8 connections per byte read.
// When all 8 bits are set (common case: active connections), a single
// byte read + clear skips all 8.  Only reads flags[] for fds whose
// accessed bit was clear.
static u64 sieve_sweep(struct sieve *s) {
    u64 expired = 0;
    u32 n_bytes = (s->max_fd + 8) / 8;

    for (u32 bi = 0; bi < n_bytes; bi++) {
        u8 acc = s->accessed[bi];
        if (acc) {
            s->accessed[bi] = 0;          // clear second-chance bits
            if (acc == 0xFF) continue;     // all 8 accessed — skip flag reads
        }

        // Only check fds whose accessed bit was clear
        u8 check = (u8)~acc;
        u32 base = bi << 3;
        while (check) {
            u32 bit = (u32)__builtin_ctz((unsigned)check);
            u32 fd = base + bit;
            check &= (u8)(check - 1);     // clear lowest set bit
            if (fd == 0) continue;
            u8 f = s->flags[fd];
            if ((f & F_RECV_ACTIVE) && !(f & F_CLOSING)) {
                s->flags[fd] = f | F_CLOSING;
                expired++;
            }
        }
    }

    return expired;
}

// ── Strategy 2: Linear (timestamp + O(N) scan) ────────────────

struct linear {
    u8  *flags;
    u64 *activity;
    u32  max_fd;
};

#define LINEAR_SIZE (MAX_CONN * (1 + 8))  // 9MB at 1M

static void linear_setup(struct linear *s, void *mem, u32 n_active) {
    s->flags    = (u8 *)mem;
    s->activity = (u64 *)((u8 *)mem + MAX_CONN);
    s->max_fd   = n_active;

    for (u32 i = 1; i <= n_active; i++) {
        s->flags[i] = F_RECV_ACTIVE;
        s->activity[i] = rdtsc();
    }
}

static inline void linear_touch(struct linear *s, u32 fd, u64 ts) {
    u8 f = s->flags[fd];
    if (f & F_CLOSING) return;
    s->activity[fd] = ts;
}

static u64 linear_sweep(struct linear *s, u64 timeout_ticks) {
    u64 now = rdtsc();
    u64 expired = 0;
    for (u32 fd = 1; fd <= s->max_fd; fd++) {
        if ((s->flags[fd] & F_RECV_ACTIVE) &&
            !(s->flags[fd] & F_CLOSING) &&
            now - s->activity[fd] > timeout_ticks) {
            s->flags[fd] |= F_CLOSING;
            expired++;
        }
    }
    return expired;
}

// ── Strategy 3: Wheel (timing wheel, RDTSC >> N quantization) ──

struct wheel {
    u8  *flags;
    u8  *epoch;       // (u8)(ts >> wheel_shift)
    u32  max_fd;
};

#define WHEEL_SIZE (MAX_CONN * 2)  // 2MB at 1M
#define TIMEOUT_EPOCHS 14          // ~28s at ~2s buckets

static u32 wheel_shift;  // computed at runtime from TSC freq

static void wheel_setup(struct wheel *w, void *mem, u32 n_active, u64 ts) {
    w->flags  = (u8 *)mem;
    w->epoch  = (u8 *)mem + MAX_CONN;
    w->max_fd = n_active;

    u8 now_epoch = (u8)(ts >> wheel_shift);
    for (u32 i = 1; i <= n_active; i++) {
        w->flags[i] = F_RECV_ACTIVE;
        w->epoch[i] = now_epoch;
    }
}

static inline void wheel_touch(struct wheel *w, u32 fd, u64 ts) {
    u8 f = w->flags[fd];
    if (f & F_CLOSING) return;
    w->epoch[fd] = (u8)(ts >> wheel_shift);
}

static u64 wheel_sweep(struct wheel *w, u64 now_ts) {
    u8 now_epoch = (u8)(now_ts >> wheel_shift);
    u64 expired = 0;
    for (u32 fd = 1; fd <= w->max_fd; fd++) {
        if ((w->flags[fd] & F_RECV_ACTIVE) &&
            !(w->flags[fd] & F_CLOSING) &&
            (u8)(now_epoch - w->epoch[fd]) > TIMEOUT_EPOCHS) {
            w->flags[fd] |= F_CLOSING;
            expired++;
        }
    }
    return expired;
}

// ── Benchmark harness ──────────────────────────────────────────

static void *alloc_zeroed(u64 size) {
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (IS_MMAP_ERR(p)) {
        _fmt_write(2, "[FATAL] mmap %lu bytes failed\n", size);
        sys_exit_group(1);
    }
    return p;
}

static void gen_batch(u32 *fds, u32 batch_size, u32 n_active, struct rng *r) {
    for (u32 i = 0; i < batch_size; i++)
        fds[i] = 1 + (u32)(rng_next(r) % n_active);
}

#define BENCH_LOOP(setup_block, touch_call, teardown_block)         \
    do {                                                            \
        setup_block;                                                \
        struct rng r;                                               \
        u32 fds[BATCH_SIZE];                                        \
        u64 ts = 1;                                                 \
        rng_init(&r, seed);                                         \
        for (u32 b = 0; b < WARMUP_BATCHES; b++) {                 \
            gen_batch(fds, BATCH_SIZE, n_active, &r);               \
            for (u32 i = 0; i < BATCH_SIZE; i++) {                  \
                u32 fd = fds[i]; (void)fd;                          \
                touch_call; ts++;                                   \
            }                                                       \
        }                                                           \
        rng_init(&r, seed ^ 0xAAAAAAAAAAAAAAAAULL);                 \
        u64 _start = rdtsc();                                       \
        for (u32 b = 0; b < MEASURE_BATCHES; b++) {                 \
            gen_batch(fds, BATCH_SIZE, n_active, &r);               \
            for (u32 i = 0; i < BATCH_SIZE; i++) {                  \
                u32 fd = fds[i]; (void)fd;                          \
                touch_call; ts++;                                   \
            }                                                       \
        }                                                           \
        cycles = rdtsc() - _start;                                  \
        teardown_block;                                             \
    } while (0)

// ── Touch benchmarks ───────────────────────────────────────────

static u64 bench_sieve(u32 n_active, u64 seed) {
    u64 cycles;
    void *mem = alloc_zeroed(SIEVE_SIZE);
    struct sieve s;
    BENCH_LOOP(
        sieve_setup(&s, mem, n_active),
        sieve_touch(&s, fd, ts),
        munmap(mem, SIEVE_SIZE)
    );
    return cycles;
}

static u64 bench_linear(u32 n_active, u64 seed) {
    u64 cycles;
    void *mem = alloc_zeroed(LINEAR_SIZE);
    struct linear s;
    BENCH_LOOP(
        linear_setup(&s, mem, n_active),
        linear_touch(&s, fd, ts),
        munmap(mem, LINEAR_SIZE)
    );
    return cycles;
}

static u64 bench_wheel(u32 n_active, u64 seed) {
    u64 cycles;
    void *mem = alloc_zeroed(WHEEL_SIZE);
    struct wheel w;
    BENCH_LOOP(
        wheel_setup(&w, mem, n_active, 1ULL << (wheel_shift + 4)),
        wheel_touch(&w, fd, ts),
        munmap(mem, WHEEL_SIZE)
    );
    return cycles;
}

// ── Sweep benchmarks ───────────────────────────────────────────

static u64 bench_sweep_sieve(u32 n_active) {
    void *mem = alloc_zeroed(SIEVE_SIZE);
    struct sieve s;
    sieve_setup(&s, mem, n_active);

    // Clear accessed bits for first half (expired), keep set for second half
    for (u32 i = 1; i <= n_active / 2; i++)
        s.accessed[i >> 3] &= (u8)~(1 << (i & 7));

    // Warmup
    for (int w = 0; w < 3; w++) {
        for (u32 i = 1; i <= n_active; i++)
            s.flags[i] &= (u8)~F_CLOSING;
        // After sweep, all accessed bits are 0.  Re-set the second half.
        for (u32 i = n_active / 2 + 1; i <= n_active; i++)
            s.accessed[i >> 3] |= (u8)(1 << (i & 7));
        sieve_sweep(&s);
    }

    // Measure
    u64 start = rdtsc();
    for (int rep = 0; rep < 100; rep++) {
        for (u32 i = 1; i <= n_active; i++)
            s.flags[i] &= (u8)~F_CLOSING;
        for (u32 i = n_active / 2 + 1; i <= n_active; i++)
            s.accessed[i >> 3] |= (u8)(1 << (i & 7));
        sieve_sweep(&s);
    }
    u64 cycles = rdtsc() - start;

    munmap(mem, SIEVE_SIZE);
    return cycles / 100;
}

static u64 bench_sweep_linear(u32 n_active) {
    void *mem = alloc_zeroed(LINEAR_SIZE);
    struct linear s;
    linear_setup(&s, mem, n_active);

    u64 now = rdtsc();
    for (u32 i = 1; i <= n_active / 2; i++)
        s.activity[i] = now - 1000000000ULL;
    for (u32 i = n_active / 2 + 1; i <= n_active; i++)
        s.activity[i] = now;

    u64 timeout = 500000000ULL;

    // Warmup
    for (int w = 0; w < 3; w++) {
        for (u32 i = 1; i <= n_active; i++)
            s.flags[i] &= (u8)~F_CLOSING;
        linear_sweep(&s, timeout);
    }

    // Measure
    u64 start = rdtsc();
    for (int rep = 0; rep < 100; rep++) {
        for (u32 i = 1; i <= n_active; i++)
            s.flags[i] &= (u8)~F_CLOSING;
        linear_sweep(&s, timeout);
    }
    u64 cycles = rdtsc() - start;

    munmap(mem, LINEAR_SIZE);
    return cycles / 100;
}

static u64 bench_sweep_wheel(u32 n_active) {
    void *mem = alloc_zeroed(WHEEL_SIZE);
    struct wheel w;

    u64 now_ts = rdtsc();
    wheel_setup(&w, mem, n_active, now_ts);

    u8 now_epoch = (u8)(now_ts >> wheel_shift);
    u8 old_epoch = (u8)(now_epoch - TIMEOUT_EPOCHS - 2);
    for (u32 i = 1; i <= n_active / 2; i++)
        w.epoch[i] = old_epoch;
    for (u32 i = n_active / 2 + 1; i <= n_active; i++)
        w.epoch[i] = now_epoch;

    // Warmup
    for (int wr = 0; wr < 3; wr++) {
        for (u32 i = 1; i <= n_active; i++)
            w.flags[i] &= (u8)~F_CLOSING;
        wheel_sweep(&w, now_ts);
    }

    // Measure
    u64 start = rdtsc();
    for (int rep = 0; rep < 100; rep++) {
        for (u32 i = 1; i <= n_active; i++)
            w.flags[i] &= (u8)~F_CLOSING;
        wheel_sweep(&w, now_ts);
    }
    u64 cycles = rdtsc() - start;

    munmap(mem, WHEEL_SIZE);
    return cycles / 100;
}

// ── TSC frequency detection ────────────────────────────────────

static u64 detect_tsc_freq(void) {
    u32 eax, ebx, ecx, edx;
    cpuid(0x15, 0, &eax, &ebx, &ecx, &edx);
    if (eax && ebx && ecx)
        return (u64)ecx * ebx / eax;
    cpuid(0x16, 0, &eax, &ebx, &ecx, &edx);
    if (eax & 0xFFFF)
        return (u64)(eax & 0xFFFF) * 1000000ULL;
    return 0;
}

static u32 compute_wheel_shift(u64 tsc_freq) {
    if (!tsc_freq) return 31;
    u64 target = tsc_freq * 2;
    u32 shift = 63 - (u32)__builtin_clzll(target);
    return shift;
}

// ── Main ───────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
    int cpu = 0;
    if (argc > 1) {
        const char *p = argv[1];
        int v = 0;
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        cpu = v;
    }

    if (cpu >= 0 && cpu < CPU_SETSIZE) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu, &cpuset);
        sched_setaffinity(0, sizeof(cpuset), &cpuset);
    }

    u64 tsc_freq = detect_tsc_freq();
    u64 tsc_mhz = tsc_freq / 1000000;
    u64 seed = rdtsc();
    u64 total_ops = (u64)MEASURE_BATCHES * BATCH_SIZE;

    wheel_shift = compute_wheel_shift(tsc_freq);
    u64 bucket_ns = tsc_mhz ? ((1ULL << wheel_shift) * 1000 / tsc_mhz) : 0;

    _fmt_write(1, "\nConnection idle-tracking microbenchmark\n");
    _fmt_write(1, "CPU: %d  |  TSC: %lu MHz  |  Wheel shift: %u (~%lu.%lus buckets)\n",
               cpu, tsc_mhz, wheel_shift, bucket_ns / 1000000000, (bucket_ns / 100000000) % 10);
    _fmt_write(1, "Warmup: %u batches  |  Measure: %u batches x %u = %lu ops\n\n",
               WARMUP_BATCHES, MEASURE_BATCHES, BATCH_SIZE, total_ops);

    static const u32 active_counts[] = { 1000, 10000, 100000, 500000, 1000000 };
    static const u32 num_counts = 5;

    for (u32 ci = 0; ci < num_counts; ci++) {
        u32 n = active_counts[ci];

        u32 sieve_kb  = (n + n / 8) / 1024;
        u32 linear_kb = n * (1 + 8) / 1024;
        u32 wheel_kb  = n * 2 / 1024;

        _fmt_write(1, "── Active: %u (Sieve: %uKB  Linear: %uKB  Wheel: %uKB)\n",
                   n, sieve_kb, linear_kb, wheel_kb);

        u64 c_sieve  = bench_sieve(n, seed);
        u64 c_linear = bench_linear(n, seed);
        u64 c_wheel  = bench_wheel(n, seed);

        u64 ns_sieve  = tsc_mhz ? (c_sieve  * 1000 / tsc_mhz) / total_ops : 0;
        u64 ns_linear = tsc_mhz ? (c_linear * 1000 / tsc_mhz) / total_ops : 0;
        u64 ns_wheel  = tsc_mhz ? (c_wheel  * 1000 / tsc_mhz) / total_ops : 0;

        _fmt_write(1, "  sieve\t%lu cyc/op\t%lu ns/op\n",  c_sieve / total_ops,  ns_sieve);
        _fmt_write(1, "  linear\t%lu cyc/op\t%lu ns/op\n", c_linear / total_ops, ns_linear);
        _fmt_write(1, "  wheel\t%lu cyc/op\t%lu ns/op\n",  c_wheel / total_ops,  ns_wheel);

        u64 sw_sieve  = bench_sweep_sieve(n);
        u64 sw_linear = bench_sweep_linear(n);
        u64 sw_wheel  = bench_sweep_wheel(n);

        u64 us_sieve  = tsc_mhz ? sw_sieve / tsc_mhz : 0;
        u64 us_linear = tsc_mhz ? sw_linear / tsc_mhz : 0;
        u64 us_wheel  = tsc_mhz ? sw_wheel / tsc_mhz : 0;

        _fmt_write(1, "  sweep_sieve:\t%lu cycles\t%lu us\n",  sw_sieve, us_sieve);
        _fmt_write(1, "  sweep_linear:\t%lu cycles\t%lu us\n", sw_linear, us_linear);
        _fmt_write(1, "  sweep_wheel:\t%lu cycles\t%lu us\n\n", sw_wheel, us_wheel);
    }

    _fmt_write(1, "Legend:\n");
    _fmt_write(1, "  sieve  = u8[] + bit-packed accessed[] (CLOCK/second-chance)\n");
    _fmt_write(1, "  linear = u8[] + u64[] timestamp, O(N) sequential scan\n");
    _fmt_write(1, "  wheel  = u8[] + u8[] epoch (RDTSC >> %u quantized)\n", wheel_shift);
    _fmt_write(1, "  sweep  = Cost of one idle scan per strategy\n\n");

    return 0;
}
