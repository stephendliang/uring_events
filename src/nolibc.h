#pragma once
// nolibc.h — freestanding replacement for glibc (x86-64 Linux only).
// Always included — freestanding replacement for glibc (x86-64 Linux only).
// Provides: kernel constants, raw syscalls, minimal formatting, _start.

// Compiler-provided (freestanding)
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

// Short type aliases (also defined in core.h for glibc/debug builds)
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  i32;
typedef int64_t  i64;

// Kernel UAPI headers
#include <asm/unistd.h>
#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <linux/time_types.h>
#include <linux/mman.h>
#include <asm-generic/mman-common.h>
#include <asm-generic/socket.h>
#include <linux/in.h>
#include <linux/tcp.h>
// Signal constants and types — defined manually to avoid conflicts with
// glibc headers pulled in by immintrin.h (via stdlib.h → sigset_t).
#define SIGINT  2
#define SIGTERM 15

#define SA_RESTORER 0x04000000

typedef unsigned long k_sigset_t;
typedef void (*__sighandler_t)(int);
typedef void (*__sigrestore_t)(void);

struct k_sigaction {
    __sighandler_t sa_handler;
    unsigned long  sa_flags;
    __sigrestore_t sa_restorer;
    k_sigset_t     sa_mask;
};

// Constants not in kernel headers

#define AF_INET       2
#define SOCK_STREAM   1
#define SOCK_NONBLOCK 0x800

struct sockaddr {
    unsigned short sa_family;
    char           sa_data[14];
};

#define MAP_FAILED ((void *)-1)

// _NSIG: kernel uses 64 signals; asm/signal.h defines NSIG=32 (historical)
#ifndef _NSIG
#define _NSIG 64
#endif

typedef volatile int sig_atomic_t;

// CPU affinity

#define CPU_SETSIZE 1024
#define _NCPUBITS   (8 * sizeof(unsigned long))

typedef struct {
    unsigned long __bits[CPU_SETSIZE / _NCPUBITS];
} cpu_set_t;

#define CPU_ZERO(set) \
    __builtin_memset((set), 0, sizeof(cpu_set_t))
#define CPU_SET(cpu, set) \
    ((set)->__bits[(cpu) / _NCPUBITS] |= (1UL << ((cpu) % _NCPUBITS)))

// Byte order

#define htons(x) ((u16)__builtin_bswap16((u16)(x)))
#define htonl(x) ((u32)__builtin_bswap32((u32)(x)))

// Raw syscall primitive (x86-64)

static inline long _syscall6(long nr, long a1, long a2, long a3,
                              long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

#define _syscall0(nr)                     _syscall6(nr,0,0,0,0,0,0)
#define _syscall1(nr,a)                   _syscall6(nr,(long)(a),0,0,0,0,0)
#define _syscall2(nr,a,b)                 _syscall6(nr,(long)(a),(long)(b),0,0,0,0)
#define _syscall3(nr,a,b,c)              _syscall6(nr,(long)(a),(long)(b),(long)(c),0,0,0)
#define _syscall4(nr,a,b,c,d)            _syscall6(nr,(long)(a),(long)(b),(long)(c),(long)(d),0,0)
#define _syscall5(nr,a,b,c,d,e)          _syscall6(nr,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),0)

// Syscall wrappers

static inline long sys_write(int fd, const void *buf, size_t count) {
    return _syscall3(__NR_write, fd, buf, count);
}

static inline int sys_close(int fd) {
    return (int)_syscall1(__NR_close, fd);
}

static inline void *sys_mmap(void *addr, size_t len, int prot,
                              int flags, int fd, long offset) {
    return (void *)_syscall6(__NR_mmap, (long)addr, len, prot, flags, fd, offset);
}

static inline int sys_munmap(void *addr, size_t len) {
    return (int)_syscall2(__NR_munmap, addr, len);
}

static inline int sys_socket(int domain, int type, int protocol) {
    return (int)_syscall3(__NR_socket, domain, type, protocol);
}

static inline int sys_setsockopt(int fd, int level, int optname,
                                  const void *optval, int optlen) {
    return (int)_syscall5(__NR_setsockopt, fd, level, optname, optval, optlen);
}

static inline int sys_bind(int fd, const void *addr, int addrlen) {
    return (int)_syscall3(__NR_bind, fd, addr, addrlen);
}

static inline int sys_listen(int fd, int backlog) {
    return (int)_syscall2(__NR_listen, fd, backlog);
}

static inline int sys_sched_setaffinity(int pid, size_t len, const void *mask) {
    return (int)_syscall3(__NR_sched_setaffinity, pid, len, mask);
}

static inline int sys_io_uring_setup(unsigned entries, void *params) {
    return (int)_syscall2(__NR_io_uring_setup, entries, params);
}

static inline int sys_io_uring_register(int fd, unsigned opcode,
                                         const void *arg, unsigned nr_args) {
    return (int)_syscall4(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

static inline long sys_io_uring_enter(int fd, unsigned to_submit,
                                       unsigned min_complete, unsigned flags,
                                       const void *arg, size_t argsz) {
    return _syscall6(__NR_io_uring_enter, fd, to_submit, min_complete,
                     flags, (long)arg, argsz);
}

static inline int sys_clock_gettime(int clk_id,
                                     struct __kernel_timespec *tp) {
    return (int)_syscall2(__NR_clock_gettime, clk_id, tp);
}

// x86-64 timestamp counter — ~20 cycles, no kernel transition
static inline u64 rdtsc(void) {
    u32 lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((u64)hi << 32) | lo;
}

static inline void cpuid(u32 leaf, u32 subleaf,
                          u32 *eax, u32 *ebx, u32 *ecx, u32 *edx) {
    __asm__ volatile ("cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(subleaf));
}

static inline int sys_rt_sigaction(int sig, const struct k_sigaction *act,
                                    struct k_sigaction *oact, size_t sigsetsize) {
    return (int)_syscall4(__NR_rt_sigaction, sig, act, oact, sigsetsize);
}

static inline _Noreturn void sys_exit_group(int status) {
    _syscall1(__NR_exit_group, status);
    __builtin_unreachable();
}

// Macro aliases: drop-in replacements for glibc functions

#define close(fd)                          sys_close(fd)
#define mmap(addr,len,prot,fl,fd,off)      sys_mmap(addr,len,prot,fl,fd,off)
#define munmap(addr,len)                   sys_munmap(addr,len)
#define socket(d,t,p)                      sys_socket(d,t,p)
#define setsockopt(fd,lev,opt,val,len)     sys_setsockopt(fd,lev,opt,val,len)
#define bind(fd,addr,len)                  sys_bind(fd,addr,len)
#define listen(fd,bl)                      sys_listen(fd,bl)
#define sched_setaffinity(pid,len,mask)    sys_sched_setaffinity(pid,len,mask)

// Signal helpers

// sa_restorer trampoline — kernel requires SA_RESTORER on x86-64
__attribute__((naked)) static void __sa_restorer(void) {
    __asm__ volatile ("mov $15, %%eax\n\tsyscall" ::: "memory");
}

static inline int k_sigaction(int sig, void (*handler)(int)) {
    struct k_sigaction sa = {
        .sa_handler  = handler,
        .sa_flags    = SA_RESTORER,
        .sa_restorer = __sa_restorer,
        .sa_mask     = 0,
    };
    return sys_rt_sigaction(sig, &sa, NULL, sizeof(k_sigset_t));
}

// Minimal stderr formatter

// Handles: %s %d %u %x %zu %p (and %% for literal %).
// Uses a 256-byte stack buffer, writes to fd via sys_write. No heap.
static inline void _fmt_write(int fd, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static inline void _fmt_write(int fd, const char *fmt, ...) {
    char buf[256];
    int pos = 0;
    va_list ap;
    va_start(ap, fmt);

    while (*fmt && pos < (int)sizeof(buf) - 1) {
        if (*fmt != '%') {
            buf[pos++] = *fmt++;
            continue;
        }
        fmt++; // skip '%'
        if (*fmt == '%') { buf[pos++] = '%'; fmt++; continue; }

        // optional 'z' length modifier
        int is_size = 0;
        if (*fmt == 'z') { is_size = 1; fmt++; }
        // optional 'l' length modifier
        int is_long = 0;
        if (*fmt == 'l') { is_long = 1; fmt++; }

        switch (*fmt) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s && pos < (int)sizeof(buf) - 1) buf[pos++] = *s++;
            break;
        }
        case 'd': {
            long v = (is_size || is_long) ? va_arg(ap, long) : (long)va_arg(ap, int);
            if (v < 0) { buf[pos++] = '-'; v = -v; }
            char tmp[20]; int n = 0;
            do { tmp[n++] = '0' + (int)(v % 10); v /= 10; } while (v);
            while (n-- && pos < (int)sizeof(buf) - 1) buf[pos++] = tmp[n];
            break;
        }
        case 'u': {
            unsigned long v = (is_size || is_long)
                ? va_arg(ap, unsigned long) : (unsigned long)va_arg(ap, unsigned int);
            char tmp[20]; int n = 0;
            do { tmp[n++] = '0' + (int)(v % 10); v /= 10; } while (v);
            while (n-- && pos < (int)sizeof(buf) - 1) buf[pos++] = tmp[n];
            break;
        }
        case 'x': case 'p': {
            unsigned long v;
            if (*fmt == 'p') {
                v = (unsigned long)va_arg(ap, void *);
                if (pos < (int)sizeof(buf) - 2) { buf[pos++] = '0'; buf[pos++] = 'x'; }
            } else {
                v = (is_size || is_long)
                    ? va_arg(ap, unsigned long) : (unsigned long)va_arg(ap, unsigned int);
            }
            char tmp[16]; int n = 0;
            do { int d = (int)(v & 0xf); tmp[n++] = (d < 10) ? '0'+d : 'a'+d-10; v >>= 4; } while (v);
            while (n-- && pos < (int)sizeof(buf) - 1) buf[pos++] = tmp[n];
            break;
        }
        default:
            buf[pos++] = '%';
            if (pos < (int)sizeof(buf) - 1) buf[pos++] = *fmt;
            break;
        }
        fmt++;
    }

    va_end(ap);
    sys_write(fd, buf, (size_t)pos);
}

// Compiler compatibility: GCC-specific pragmas that Clang/ICX don't need.
// GCC converts explicit loops back into memset/memcpy calls (infinite recursion
// in freestanding); Clang doesn't do this transformation.
#ifdef __clang__
#define GCC_PUSH_NO_LOOP_PATTERNS
#define GCC_POP_OPTIONS
#else
#define GCC_PUSH_NO_LOOP_PATTERNS \
    _Pragma("GCC push_options") \
    _Pragma("GCC optimize(\"no-tree-loop-distribute-patterns\")")
#define GCC_POP_OPTIONS _Pragma("GCC pop_options")
#endif

// externally_visible: GCC-only, prevents LTO from stripping symbols.
// __attribute__((used)) alone suffices for Clang/ICX.
#ifdef __clang__
#define ATTR_EXT_VIS
#else
#define ATTR_EXT_VIS , externally_visible
#endif

// _start entry point (emitted once — guard with NOLIBC_MAIN)

#ifdef NOLIBC_MAIN

// Freestanding memset/memcpy
// GCC emits implicit memset/memcpy for large aggregate init even
// in -ffreestanding.  Provide linker symbols.  Hot-path code uses
// SIMD primitives in util.h; these only fire for compiler-generated
// calls (startup, large struct zero-init).
// The pragma prevents GCC from converting the loop back into a
// memset/memcpy call (infinite recursion).

// Aliasing-safe u64 for memset/memcpy - avoids strict aliasing UB
typedef u64 __attribute__((may_alias)) u64_alias;

GCC_PUSH_NO_LOOP_PATTERNS

__attribute__((noinline, used ATTR_EXT_VIS))
void *memset(void *s, int c, size_t n) {
    u8 *p = (u8 *)s;
    u64_alias fill = (u8)c * 0x0101010101010101ULL;
    while (n >= 8) { *(u64_alias *)p = fill; p += 8; n -= 8; }
    while (n--) *p++ = (u8)c;
    return s;
}

__attribute__((noinline, used ATTR_EXT_VIS))
void *memcpy(void *dst, const void *src, size_t n) {
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    while (n >= 8) { *(u64_alias *)d = *(const u64_alias *)s; d += 8; s += 8; n -= 8; }
    while (n--) *d++ = *s++;
    return dst;
}

GCC_POP_OPTIONS

__attribute__((used ATTR_EXT_VIS))
int main(int argc, char *argv[]);

__attribute__((naked, noreturn, used ATTR_EXT_VIS))
void _start(void) {
    __asm__ volatile (
        "xor  %%ebp, %%ebp\n\t"       /* ABI: clear frame pointer */

        /* --- static-pie self-relocation ----------------------------- */
        /* With -static-pie -nostartfiles, no crt processes relocations */
        /* for us.  Walk .rela.dyn and apply R_X86_64_RELATIVE entries  */
        /* (type 8) before touching anything that needs a relocation.   */
        /* All addressing here is RIP-relative — no relocs needed.      */

        "lea  __ehdr_start(%%rip), %%r12\n\t"  /* r12 = runtime base   */
        "lea  _DYNAMIC(%%rip), %%r13\n\t"      /* r13 = &_DYNAMIC[0]   */

        /* Scan _DYNAMIC for DT_RELA (7) and DT_RELASZ (8) */
        "xor  %%r14d, %%r14d\n\t"              /* r14 = rela ptr       */
        "xor  %%r15d, %%r15d\n\t"              /* r15 = rela size      */
    "1:\n\t"
        "movq 0(%%r13), %%rax\n\t"             /* d_tag                */
        "test %%rax, %%rax\n\t"                /* DT_NULL → done       */
        "jz   3f\n\t"
        "cmp  $7, %%rax\n\t"                   /* DT_RELA              */
        "jne  2f\n\t"
        "movq 8(%%r13), %%r14\n\t"             /* d_val = rela offset  */
        "add  %%r12, %%r14\n\t"                /* absolute rela ptr    */
        "jmp  4f\n\t"
    "2:\n\t"
        "cmp  $8, %%rax\n\t"                   /* DT_RELASZ            */
        "jne  4f\n\t"
        "movq 8(%%r13), %%r15\n\t"             /* d_val = total size   */
    "4:\n\t"
        "add  $16, %%r13\n\t"                  /* next Elf64_Dyn       */
        "jmp  1b\n\t"

        /* Apply relocations: r14 = start, r15 = remaining bytes */
    "3:\n\t"
        "test %%r14, %%r14\n\t"                /* no DT_RELA found?    */
        "jz   6f\n\t"
    "5:\n\t"
        "test %%r15, %%r15\n\t"                /* bytes left?          */
        "jz   6f\n\t"
        "movq 8(%%r14), %%rax\n\t"             /* r_info               */
        "cmp  $8, %%eax\n\t"                   /* R_X86_64_RELATIVE?   */
        "jne  7f\n\t"
        "movq 0(%%r14), %%rcx\n\t"             /* r_offset             */
        "movq 16(%%r14), %%rdx\n\t"            /* r_addend             */
        "add  %%r12, %%rdx\n\t"                /* base + addend        */
        "movq %%rdx, (%%r12,%%rcx)\n\t"        /* *(base+offset) = ^  */
    "7:\n\t"
        "add  $24, %%r14\n\t"                  /* sizeof(Elf64_Rela)   */
        "sub  $24, %%r15\n\t"
        "jmp  5b\n\t"
        /* --- end self-relocation ------------------------------------ */

    "6:\n\t"
        "mov  (%%rsp), %%edi\n\t"      /* argc */
        "lea  8(%%rsp), %%rsi\n\t"     /* argv */
        "and  $-16, %%rsp\n\t"         /* align stack to 16 */
        "call main\n\t"
        "mov  %%eax, %%edi\n\t"        /* exit code */
        "mov  $231, %%eax\n\t"         /* __NR_exit_group */
        "syscall\n\t"
        "ud2"
        ::: "memory"
    );
}

#endif // NOLIBC_MAIN
