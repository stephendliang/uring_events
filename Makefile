CC           ?= gcc
BINARY       := event
BINARY_DEBUG := event-debug
SRC          := src/main.c src/event.c src/uring.c
HEADERS      := $(wildcard src/*.h)

CFLAGS_COMMON := -std=gnu11 -Wall -Wextra -Werror \
    -ffreestanding -nostdlib -nostartfiles -static-pie -fPIE \
    -fno-stack-protector

CFLAGS_RELEASE := $(CFLAGS_COMMON) -O3 -march=native -mtune=native \
    -fomit-frame-pointer -fno-plt -ffast-math \
    -flto -fno-semantic-interposition -fvisibility=hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -DNDEBUG

CFLAGS_DEBUG := $(CFLAGS_COMMON) -O0 -g -DDEBUG

BENCH_SRC    := src/bench_main.c src/bench.c src/uring.c

.PHONY: release debug bench bench-debug clean

release: $(BINARY)

$(BINARY): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS_RELEASE) $(SRC) -o $(BINARY)

debug: $(BINARY_DEBUG)

$(BINARY_DEBUG): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS_DEBUG) $(SRC) -o $(BINARY_DEBUG)

bench:
	$(CC) $(CFLAGS_RELEASE) $(BENCH_SRC) -o bench

bench-debug:
	$(CC) $(CFLAGS_DEBUG) $(BENCH_SRC) -o bench-debug

clean:
	rm -f $(BINARY) $(BINARY_DEBUG) bench bench-debug
