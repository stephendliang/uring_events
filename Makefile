CC       ?= gcc
BINARY   := event
SRC      := src/main.c src/event.c
HEADERS  := $(wildcard src/*.h)

CFLAGS_COMMON := -std=gnu11 -Wall -Wextra -Werror

CFLAGS_RELEASE := $(CFLAGS_COMMON) -O3 -march=native -mtune=native \
    -fomit-frame-pointer -fno-stack-protector -fno-plt -ffast-math \
    -flto -fno-semantic-interposition -fvisibility=hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -DNDEBUG

CFLAGS_DEBUG := $(CFLAGS_COMMON) -O0 -g -DDEBUG

CFLAGS_ZC := $(CFLAGS_RELEASE) -DENABLE_ZC

.PHONY: release debug zc clean

release: $(BINARY)

$(BINARY): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS_RELEASE) $(SRC) -o $(BINARY)

debug: $(SRC) $(HEADERS)
	$(CC) $(CFLAGS_DEBUG) $(SRC) -o $(BINARY)

zc: $(SRC) $(HEADERS)
	$(CC) $(CFLAGS_ZC) $(SRC) -o $(BINARY)

clean:
	rm -f $(BINARY)
