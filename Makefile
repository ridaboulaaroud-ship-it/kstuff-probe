PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
SDK_BIN := $(PS5_PAYLOAD_SDK)/bin
CC := $(or $(wildcard $(SDK_BIN)/prospero-clang),$(wildcard $(SDK_BIN)/x86_64-ps5-prospero-clang),clang)

CFLAGS  = -O2 -Wall -Wextra -std=gnu11 -ffreestanding -fno-builtin \
          -fno-stack-protector -mno-red-zone
LDFLAGS = -nostdlib -Wl,-T,payload.ld -Wl,--gc-sections -Wl,-z,max-page-size=0x4000

all: kstuff-probe.elf
kstuff-probe.elf: kstuff-probe.o payload.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ kstuff-probe.o
kstuff-probe.o: kstuff-probe.c
	$(CC) $(CFLAGS) -c -o $@ $<
clean:
	rm -f kstuff-probe.o kstuff-probe.elf
.PHONY: all clean
