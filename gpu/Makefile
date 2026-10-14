SDK := $(shell xcrun --show-sdk-path)
SWIFTC := xcrun swiftc
CC := xcrun clang
TARGET := darkphoenix-metal
TRIPLE := arm64-apple-macosx27.0
SRCS := AES.swift Linear.swift MetalOracle.swift Oracle.swift Fault.swift Attack.swift main.swift
CFLAGS := -O3 -std=c11 -Wall -Wextra -mcpu=native -target $(TRIPLE) -isysroot $(SDK)

.PHONY: all selftest bench clean

all: $(TARGET)

aes_aese.o: aes_aese.c aes_aese.h
	$(CC) $(CFLAGS) -c aes_aese.c -o $@

$(TARGET): $(SRCS) Shaders.metal aes_aese.o aes_aese.h
	$(SWIFTC) -swift-version 5 -O -sdk $(SDK) -target $(TRIPLE) \
		-import-objc-header aes_aese.h \
		-framework Metal -framework Foundation -o $@ $(SRCS) aes_aese.o

selftest: $(TARGET)
	./$(TARGET) --selftest

bench: $(TARGET)
	./$(TARGET) --bench 1048576

clean:
	rm -f $(TARGET) aes_aese.o
