# Makefile — hybrid_v4
CC       := clang
BPFTOOL  := bpftool
ARCH     := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
MULTIARCH := $(shell uname -m)-linux-gnu
VMLINUX  := vmlinux.h
BPF_CFLAGS := -target bpf -O2 -g -Wall -Wno-unused-variable \
              -I. -I/usr/include/bpf -D__TARGET_ARCH_$(ARCH) -D__BPF__ \
              -I/usr/include/$(MULTIARCH)
CFLAGS   := -O2 -Wall -g -I. -I/usr/include/bpf
LDFLAGS  := -lbpf -lelf -lz

.PHONY: all clean

all: fd_tracker

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

fd_tracker.bpf.o: fd_tracker.bpf.c fd_tracker.h $(VMLINUX)
	$(CC) $(BPF_CFLAGS) -c $< -o $@

fd_tracker.skel.h: fd_tracker.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

fd_tracker: fd_tracker.c fd_tracker.skel.h fd_tracker.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f fd_tracker.bpf.o fd_tracker.skel.h fd_tracker $(VMLINUX)
