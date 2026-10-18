# Validation

`validate.py` builds both tools and runs two short functional checks on Linux.
It needs the build dependencies in the project README, access to
`/sys/kernel/btf/vmlinux`, and passwordless `sudo` for the tools. Run it from a
writable copy of this repository:

```bash
python3 tests/validate.py --output /tmp/ebpf-validation-results
```

The TCP check opens three local IPv4 connections from separate Python client
processes, followed by a 50-connection burst from another client. It requires
two events per connection, the expected outbound client PIDs, and the server
PID on every inbound row.

The scheduler check runs `sched_lat` for 10 seconds at baseline and for 10
seconds with two CPU-bound `yes` processes per logical CPU plus up to four
Python processes waking every 10 ms. It counts events in the displayed 1 ms
and higher histogram buckets. The tools collect system-wide events, so these
are short functional observations, not an overhead benchmark or a controlled
comparison of workload percentiles.

The script saves raw stdout, stderr, readable scheduler output, and
`summary.json`. The [post-fix run](results/2026-10-18-post-fix-vm/README.md)
documents the current implementation. The [earlier run](results/2026-10-18-vm/README.md)
records the inbound PID defect before the accept hook was added.
