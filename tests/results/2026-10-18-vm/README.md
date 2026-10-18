# Linux VM validation — October 18, 2026

This is a later validation run of the May 2026 project. The project author
also recalls testing the tools interactively during development and recording
the README's scheduler numbers. No raw output from that earlier run is saved
in this repository.

## Environment and procedure

- Ubuntu Linux VM, kernel `6.8.0-106-generic`, `aarch64`, four logical CPUs.
- Built both programs with `make` after generating `vmlinux.h` from the VM's BTF.
- Ran [`tests/validate.py`](../../validate.py) from a writable copy of the source.
- Tested TCP with three local IPv4 client processes. Sampled scheduler latency
  for 10 seconds at baseline and 10 seconds with eight CPU-bound `yes`
  processes plus four Python processes waking every 10 ms.

## Observations

| Check | Result |
| --- | --- |
| Build | Both BPF programs and userspace programs built successfully. |
| TCP | Six loopback connection events appeared for three client connections. All three outbound client PIDs appeared. |
| Scheduler baseline | Nine one-second histogram windows; 901 events, one in a displayed 1 ms or higher bucket. |
| Scheduler contention | Nine one-second histogram windows; 4,475 events, 152 in displayed 1 ms or higher buckets. One event reached the displayed 65 ms bucket. |

The TCP output also showed a limitation: the server process PID was `1793`,
but the server-side rows reported client PIDs `1818`, `1819`, and `1820`.
Outbound attribution passed this check; inbound process attribution did not.
See [tcp.raw](tcp.raw) and [summary.json](summary.json).

The scheduler results show a millisecond-range tail in this short contended
run. They do not measure the tools' CPU overhead. Because the workload changes
which processes wake up, the event counts are not a controlled estimate of
performance impact. Histogram bucket labels are rounded for display: the
`1 ms` bucket begins at 1,024 µs. The run also does not reproduce the earlier
README example's exact `stress --cpu 4` workload.

Read the scheduler output without terminal control characters:
[baseline](scheduler-baseline.txt) and [contention](scheduler-contention.txt).
The original stdout is also saved as `scheduler-baseline.raw` and
`scheduler-contention.raw`. The `.err` files are empty, indicating that these
runs printed no stderr output.
