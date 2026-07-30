# xfuzz — XNU kernel fuzzer (arm64 macOS)
CC      ?= clang
CFLAGS  ?= -O2 -g -std=c11 -Wall -Wextra -Wno-deprecated-declarations \
           -Wno-unused-parameter -Iinclude -arch arm64
LDFLAGS ?= -framework IOKit -framework CoreFoundation

SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,build/%.o,$(SRC))
BIN := xfuzz

.PHONY: all clean run smoke dryrun

all: $(BIN)

build:
	@mkdir -p build

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)
	@echo "built $(BIN)"

# Validate the engine without touching the kernel.
dryrun: $(BIN)
	./$(BIN) --dry-run --max-execs 20000 --workdir ./run --verbose

# Short safe smoke test against the live kernel (safe-mode on).
smoke: $(BIN)
	./$(BIN) --max-execs 5000 --workdir ./run

clean:
	rm -rf build $(BIN) $(BIN).dSYM
