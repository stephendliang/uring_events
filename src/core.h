#pragma once

#include <stdint.h>

#ifdef NOLIBC
#include "nolibc.h"
#else
#include <stdio.h>
#endif

#ifndef NOLIBC
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  i32;
typedef int64_t  i64;
#endif

#ifdef DEBUG
  #define LOG_INFO(fmt, ...)  fprintf(stderr, "[INFO] " fmt "\n", ##__VA_ARGS__)
  #define LOG_WARN(fmt, ...)  fprintf(stderr, "[WARN] " fmt "\n", ##__VA_ARGS__)
  #define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
  #define LOG_BUG(fmt, ...)   fprintf(stderr, "[BUG] " fmt "\n", ##__VA_ARGS__)
  #define DEBUG_ONLY(x)       x
#else
  #define LOG_INFO(fmt, ...)  ((void)0)
  #define LOG_WARN(fmt, ...)  ((void)0)
  #define LOG_ERROR(fmt, ...) ((void)0)
  #define LOG_BUG(fmt, ...)   ((void)0)
  #define DEBUG_ONLY(x)       ((void)0)
#endif

#ifdef NOLIBC
#define LOG_FATAL(fmt, ...) _fmt_write(2, "[FATAL] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_FATAL(fmt, ...) do { \
    fprintf(stderr, "[FATAL] " fmt "\n", ##__VA_ARGS__); \
} while(0)
#endif

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define prefetch_r(addr) __builtin_prefetch((addr), 0, 3)
