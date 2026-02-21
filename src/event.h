#ifndef EVENT_H
#define EVENT_H
#include "core.h"
int server_run(u16 port, int cpu);
#ifdef MULTICORE
#define MAX_WORKERS 4
int server_start(u16 port, int cpu_start, int num_workers);
#endif
#endif
