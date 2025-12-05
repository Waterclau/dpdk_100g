# Makefile for MIRA Detector with ML Integration

PKGCONF ?= pkg-config

# DPDK flags
PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
CFLAGS += -Wall -Wextra
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)

# LightGBM flags (embedded ML)
CFLAGS += -I/usr/local/include
LDFLAGS_SHARED += -L/usr/local/lib -l_lightgbm

# Source files
SRCS = mira_ddos_detector_ml.c ml_inference.c
OBJS = $(SRCS:.c=.o)

TARGET = mira_ddos_detector_ml

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS_SHARED)
	@echo "Build complete: $(TARGET)"
	@echo "Run with: sudo ./$(TARGET) -l 0-15 -n 4 -w <PCI_ADDR> -- -p 0"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
	@echo "Clean complete"

.PHONY: all clean
