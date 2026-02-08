#pragma once

#include "nolibc.h"

#ifdef DEBUG
  #define LOG_INFO(fmt, ...)  _fmt_write(2, "[INFO] " fmt "\n", ##__VA_ARGS__)
  #define LOG_WARN(fmt, ...)  _fmt_write(2, "[WARN] " fmt "\n", ##__VA_ARGS__)
  #define LOG_ERROR(fmt, ...) _fmt_write(2, "[ERROR] " fmt "\n", ##__VA_ARGS__)
  #define LOG_BUG(fmt, ...)   _fmt_write(2, "[BUG] " fmt "\n", ##__VA_ARGS__)
  #define DEBUG_ONLY(x)       x
#else
  #define LOG_INFO(fmt, ...)  ((void)0)
  #define LOG_WARN(fmt, ...)  ((void)0)
  #define LOG_ERROR(fmt, ...) ((void)0)
  #define LOG_BUG(fmt, ...)   ((void)0)
  #define DEBUG_ONLY(x)       ((void)0)
#endif

#define LOG_FATAL(fmt, ...) _fmt_write(2, "[FATAL] " fmt "\n", ##__VA_ARGS__)

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define prefetch_r(addr) __builtin_prefetch((addr), 0, 3)
