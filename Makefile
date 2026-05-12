CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := arm64

CFLAGS  := -g -O2 -Wall
BPFCFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.

.PHONY: all clean

all: tcp_tracker sched_lat

tcp_tracker.bpf.o: tcp_tracker.bpf.c vmlinux.h
	$(CLANG) $(BPFCFLAGS) -c $< -o $@

tcp_tracker.skel.h: tcp_tracker.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

tcp_tracker: tcp_tracker.c tcp_tracker.skel.h
	$(CLANG) $(CFLAGS) -I. $< -lbpf -o $@

sched_lat.bpf.o: sched_lat.bpf.c vmlinux.h
	$(CLANG) $(BPFCFLAGS) -c $< -o $@

sched_lat.skel.h: sched_lat.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

sched_lat: sched_lat.c sched_lat.skel.h
	$(CLANG) $(CFLAGS) -I. $< -lbpf -o $@

clean:
	rm -f tcp_tracker.bpf.o tcp_tracker.skel.h tcp_tracker
	rm -f sched_lat.bpf.o sched_lat.skel.h sched_lat
