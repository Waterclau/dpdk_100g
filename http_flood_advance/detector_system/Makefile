# Makefile for HTTP Flood Detector with DPDK

APP = http_flood_detector

SRCS-y := http_flood_detector.c

PKGCONF ?= pkg-config

# Default target
all: $(APP)

# Build with pkg-config
$(APP): $(SRCS-y) Makefile
	$(CC) $(SRCS-y) -o $(APP) \
		$$($(PKGCONF) --cflags --libs libdpdk) \
		-O3 -march=native -Wall -Wextra \
		-lm

clean:
	rm -f $(APP) *.o

.PHONY: all clean
