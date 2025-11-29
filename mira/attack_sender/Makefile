# SPDX-License-Identifier: BSD-3-Clause

APP = dpdk_pcap_sender

# DPDK configuration
PKGCONF ?= pkg-config
PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)

CFLAGS += -O3 -g $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -lpcap
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk) -lpcap

ifeq ($(MAKECMDGOALS),static)
LDFLAGS = $(LDFLAGS_STATIC)
else
LDFLAGS = $(LDFLAGS_SHARED)
endif

CFLAGS += -DALLOW_EXPERIMENTAL_API

build/$(APP): dpdk_pcap_sender.c Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) dpdk_pcap_sender.c -o build/$(APP) $(LDFLAGS)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -rf build
