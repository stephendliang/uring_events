#define NOLIBC_MAIN

#include "core.h"
#include "event.h"

// Input validation (startup only)
static inline int parse_int(const char *str, int min, int max, const char *name) {
    long val = 0;
    const char *p = str;
    if (*p == '\0') goto bad;
    while (*p) {
        if (*p < '0' || *p > '9') goto bad;
        val = val * 10 + (*p - '0');
        if (val > max) goto bad;
        p++;
    }
    if (val < min) goto bad;
    return (int)val;
bad:
    LOG_FATAL("Invalid %s: '%s' (must be %d-%d)", name, str, min, max);
    return -1;
}

int main(int argc, char *argv[]) {
    u16 port = 8080;
    int cpu = 0;

    if (argc > 1) {
        int p = parse_int(argv[1], 1, 65535, "port");
        if (p < 0) return 1;
        port = (u16)p;
    }
    if (argc > 2) {
        cpu = parse_int(argv[2], 0, CPU_SETSIZE - 1, "cpu");
        if (cpu < 0) return 1;
    }

    return server_run(port, cpu);
}
