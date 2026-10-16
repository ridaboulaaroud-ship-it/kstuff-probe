# kstuff-probe -- build via le SDK PS5 officiel
# Le chemin du SDK est fourni par la variable PS5_PAYLOAD_SDK.

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
  ifneq ($(wildcard $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk),)
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
  else ifneq ($(wildcard $(PS5_PAYLOAD_SDK)/lib/prospero.mk),)
    include $(PS5_PAYLOAD_SDK)/lib/prospero.mk
  else
    $(error prospero.mk introuvable sous $(PS5_PAYLOAD_SDK))
  endif
else
  $(error PS5_PAYLOAD_SDK non defini)
endif

ELF    := kstuff-probe.elf
CFLAGS := -Wall -g -O2

all: $(ELF)

$(ELF): kstuff-probe.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ELF)

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^
