# Post-fix Linux VM validation — October 18, 2026

This run validates the current project after adding server PID attribution at
`fexit/inet_csk_accept`. It is distinct from the author's earlier interactive
test recorded in the project README; the original raw output was not retained.

## Environment and workload

- Ubuntu Linux VM, kernel `6.8.0-106-generic`, `aarch64`, four logical CPUs.
- Generated `vmlinux.h` from this kernel's BTF and built both tools with `make`.
- Used [`tests/validate.py`](../../validate.py) to open three separate-process
  localhost TCP connections plus a 50-connection burst from a fourth client.
- Ran the scheduler profiler for 10 seconds at baseline and 10 seconds with
  eight CPU-bound `yes` processes plus four Python processes waking every
  10 ms. Each capture yielded nine one-second histogram windows.

## Results

| Check | Observed result |
| --- | --- |
| Build | Both BPF programs and userspace programs built successfully. |
| TCP | 106 of 106 expected close events appeared for 53 connections. All four outbound client PIDs appeared; every server-side row reported the actual server PID. |
| Scheduler baseline | 879 wakeup-to-run events, three in displayed 1 ms or higher buckets. |
| Scheduler contention | 4,692 wakeup-to-run events, 85 in displayed 1 ms or higher buckets. |

The TCP check verifies the loopback workload and its process attribution. It
does not establish behavior for every application or network configuration.
The scheduler check shows a millisecond-range tail under this specific
contention workload. The event populations differ between baseline and load,
so this is not a controlled estimate of performance impact. The test did not
measure either tool's CPU overhead or TCP throughput. Histogram bucket labels
are rounded; the displayed `1 ms` bucket begins at 1,024 µs.

Evidence: [summary.json](summary.json), [TCP events](tcp.raw), readable
[baseline](scheduler-baseline.txt) and [contention](scheduler-contention.txt)
histograms. The original scheduler stdout is also saved as `.raw` files; the
`.err` files are empty.
