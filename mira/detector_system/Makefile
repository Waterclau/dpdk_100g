# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 MIRA Project

# Makefile for MIRA DDoS Detector
# Compares against MULTI-LF (2025) detection latency

APP = mira_ddos_detector

SRCS-y := mira_ddos_detector.c

# DPDK configuration
PKGCONF ?= pkg-config

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

# Application flags
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -I.
CFLAGS += -Wall -Wextra
CFLAGS += -g

# CPU-specific optimizations for high-performance packet processing
CFLAGS += -march=native -mtune=native
CFLAGS += -funroll-loops
CFLAGS += -ffast-math
CFLAGS += -flto
LDFLAGS += -flto

ifeq ($(V),1)
CFLAGS += -DVERBOSE_DEBUG
endif

# Build rules
.PHONY: all clean

all: $(APP)

$(APP): $(SRCS-y) Makefile $(PC_FILE)
	$(CC) $(CFLAGS) $(SRCS-y) -o $(APP) $(LDFLAGS) $(LDFLAGS_STATIC)
	@echo ""
	@echo "Build successful! Binary: ./$(APP)"
	@echo ""

clean:
	rm -f $(APP)
	@echo "Clean complete"

.DEFAULT_GOAL := all
