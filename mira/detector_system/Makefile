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

ifeq ($(V),1)
CFLAGS += -DVERBOSE_DEBUG
endif

# Build rules
build/$(APP): $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP)
	rmdir build 2>/dev/null || true

.PHONY: all
all: build/$(APP)

.DEFAULT_GOAL := all
