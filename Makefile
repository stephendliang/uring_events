CC       ?= gcc
BINARY   := event
SRC      := src/main.c src/event.c
HEADERS  := $(wildcard src/*.h)

CFLAGS_COMMON := -std=gnu11 -Wall -Wextra -Werror

CFLAGS_RELEASE := $(CFLAGS_COMMON) -O3 -march=native -mtune=native \
    -ffreestanding -nostdlib -nostartfiles -static \
    -fomit-frame-pointer -fno-stack-protector -fno-plt -ffast-math \
    -flto -fno-semantic-interposition -fvisibility=hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -DNDEBUG -DNOLIBC

CFLAGS_DEBUG := $(CFLAGS_COMMON) -O0 -g -DDEBUG

.PHONY: release debug clean

release: $(BINARY)

$(BINARY): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS_RELEASE) $(SRC) -o $(BINARY)

debug: $(SRC) $(HEADERS)
	$(CC) $(CFLAGS_DEBUG) $(SRC) -o $(BINARY)

clean:
	rm -f $(BINARY)
