SDK := $(shell xcrun --show-sdk-path)
SWIFTC := xcrun swiftc
TARGET := darkphoenix-metal
SRCS := AES.swift Linear.swift MetalOracle.swift Oracle.swift Fault.swift Attack.swift main.swift

.PHONY: all selftest bench clean

all: $(TARGET)

$(TARGET): $(SRCS) Shaders.metal
	$(SWIFTC) -swift-version 5 -O -sdk $(SDK) -target arm64-apple-macosx27.0 \
		-framework Metal -framework Foundation -o $@ $(SRCS)

selftest: $(TARGET)
	./$(TARGET) --selftest

bench: $(TARGET)
	./$(TARGET) --bench 1048576

clean:
	rm -f $(TARGET)
