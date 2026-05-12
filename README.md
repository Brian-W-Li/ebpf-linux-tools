# ebpf-linux-tools

Two lightweight Linux observability tools written in C using libbpf + CO-RE. Both attach directly to kernel tracepoints via eBPF — no kernel modules, no reboot, no runtime compilation on the target machine.

Built from scratch as a way to learn eBPF internals: the verifier, BPF maps, ring buffers, and the libbpf skeleton workflow.

---

## Tools

### `tcp_tracker` — Per-process TCP connection tracker

Hooks the `inet_sock_set_state` kernel tracepoint to observe every TCP connection on the system. Captures the originating PID and process name at `SYN_SENT` (the only moment that runs in the calling process's context), records a start timestamp at `ESTABLISHED`, and emits a completed event at `TCP_CLOSE`.

Results stream live to stdout via a ring buffer:

```
PID     COMM             SRC                      DST                      DURATION
------- ---------------- ------------------------ ------------------------ ----------
4606    curl             192.168.5.15:57426       104.20.23.154:443        78.76 ms
4608    curl             192.168.5.15:54114       34.223.124.45:80         90.01 ms
4617    curl             192.168.5.15:55542       142.251.215.174:443      148.49 ms
4618    git-remote-http  192.168.5.15:44056       140.82.116.3:443         15001.60 ms
```

**Internals:**
- Hash map keyed by socket pointer tracks per-connection state across multiple tracepoint firings
- Ring buffer streams completed `(pid, comm, src, dst, duration_ns)` events to userspace
- Handles both outbound (PID captured at `SYN_SENT`) and inbound (PID captured at `ESTABLISHED`) connections

---

### `sched_lat` — Scheduler run queue latency histogram

Hooks `sched_wakeup` and `sched_switch` to measure the gap between when a process becomes runnable and when the scheduler actually gives it CPU time. Buckets latencies into a power-of-2 log-scale histogram and redraws live every second.

```
Scheduler Run Queue Latency
============================
bucket       count   distribution
  1 µs :      1423   |████████████████████████████████|
  2 µs :       891   |████████████████████            |
  4 µs :       234   |█████                           |
  8 µs :        67   |█                               |
 16 µs :        12   |                                |
 32 µs :         3   |                                |
 64 µs :         1   |                                |
128 µs :         0   |                                |
```

Under load (e.g. `stress --cpu 4`) you can watch the distribution shift from sub-10µs out to 2–4ms, then snap back when the stress process is killed.

**Internals:**
- Hash map keyed by PID stores wakeup timestamps from `sched_wakeup`
- `sched_switch` computes delta for the incoming process and increments a shared array map histogram
- Userspace polls the array map every second and redraws in place using ANSI escape codes

---

## Stack

- **libbpf + CO-RE** — compiles once, runs on any kernel with BTF enabled (no LLVM on target, no kernel headers, no recompilation)
- **clang 18** — compiles `.bpf.c` to BPF bytecode
- **bpftool** — generates type-safe skeleton headers from BPF objects
- **vmlinux.h** — generated from the running kernel's BTF blob; not checked in

---

## Requirements

- Linux kernel **5.15+** with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
  - Verify: `ls /sys/kernel/btf/vmlinux`
- `clang` + `llvm`
- `libbpf-dev`
- `bpftool` (via `linux-tools-$(uname -r)`)
- `build-essential`

On Ubuntu 22.04+:
```bash
sudo apt install clang llvm libbpf-dev build-essential linux-tools-common linux-tools-$(uname -r)
```

---

## Build

```bash
# generate vmlinux.h from your running kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# build both tools
make

# or individually
make tcp_tracker
make sched_lat
```

---

## Run

Both tools require root (or `CAP_BPF` + `CAP_PERFMON`):

```bash
sudo ./tcp_tracker
```

```bash
sudo ./sched_lat
```

To generate interesting scheduler latency data:
```bash
# in a second terminal
stress --cpu 4 --timeout 10
```

---

## Project Structure

```
.
├── Makefile
├── tcp_tracker.bpf.c   # kernel-side BPF program (TCP tracepoint)
├── tcp_tracker.c       # userspace loader and ring buffer consumer
├── sched_lat.bpf.c     # kernel-side BPF program (scheduler tracepoints)
└── sched_lat.c         # userspace loader and histogram display
```

`vmlinux.h`, compiled objects, skeleton headers, and binaries are excluded from the repo — generated at build time from your running kernel.
