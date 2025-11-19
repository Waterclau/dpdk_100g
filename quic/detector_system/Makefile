# SPDX-License-Identifier: BSD-3-Clause
# QUIC Optimistic ACK Detector Makefile

APP = quic_optimistic_ack_detector

SRCS-y := quic_optimistic_ack_detector.c

PKGCONF ?= pkg-config

# Build using pkg-config variables
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

# Additional flags
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -Wall -Wextra

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

# Default target - build in current directory for compatibility
$(APP): $(SRCS-y) Makefile
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS_SHARED)

.PHONY: clean
clean:
	rm -f build/$(APP)-static build/$(APP)-shared $(APP)
	@rmdir --ignore-fail-on-non-empty build 2>/dev/null || true

.PHONY: all
all: $(APP)

.DEFAULT_GOAL := $(APP)
