# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025

# Binary names
APP1 = baseline_traffic_gen
APP2 = benign_traffic_gen

# Source files
SRCS1 := baseline_traffic_dpdk.c
SRCS2 := benign_traffic_dpdk.c

# Build using pkg-config variables if possible
ifeq ($(shell pkg-config --exists libdpdk && echo 0),0)

all: shared
.PHONY: shared static
shared: build/$(APP1)-shared build/$(APP2)-shared
	ln -sf $(APP1)-shared build/$(APP1)
	ln -sf $(APP2)-shared build/$(APP2)
static: build/$(APP1)-static build/$(APP2)-static
	ln -sf $(APP1)-static build/$(APP1)
	ln -sf $(APP2)-static build/$(APP2)

PKGCONF ?= pkg-config

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -Wall -Wextra -Werror
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -lm
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk) -lm

build/$(APP1)-shared: $(SRCS1) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS1) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP1)-static: $(SRCS1) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS1) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build/$(APP2)-shared: $(SRCS2) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS2) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP2)-static: $(SRCS2) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS2) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP1) build/$(APP1)-static build/$(APP1)-shared
	rm -f build/$(APP2) build/$(APP2)-static build/$(APP2)-shared
	test -d build && rmdir -p build || true

else

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, detect a build directory, by looking for a path with a .config
RTE_TARGET ?= $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))

include $(RTE_SDK)/mk/rte.vars.mk

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -DALLOW_EXPERIMENTAL_API

include $(RTE_SDK)/mk/rte.extapp.mk

endif
