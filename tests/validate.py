#!/usr/bin/env python3
"""Build and exercise both eBPF tools on a writable Linux checkout.

Requires the packages listed in README.md and passwordless sudo for the two
tools. The workload uses only Python and coreutils; it needs no network access.
"""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
ROW = re.compile(r"^\s*(<\s*1|\d+)\s+(us|ms|s)\s+:\s+(\d+)\b", re.M)


def announce(message):
    print(message, flush=True)


def build():
    announce("Generating vmlinux.h and building both tools...")
    with (ROOT / "vmlinux.h").open("wb") as output:
        subprocess.run(
            ["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"],
            stdout=output, check=True,
        )
    subprocess.run(["make"], cwd=ROOT, check=True)


def run_tool(name, seconds, stdout_path, stderr_path):
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        process = subprocess.Popen(
            ["timeout", "--signal=INT", "--kill-after=3s", str(seconds),
             "sudo", "-n", str(ROOT / name)],
            stdout=out, stderr=err,
        )
        return process


def finish_tool(process, stderr_path):
    status = process.wait(timeout=20)
    if status not in (0, 124):
        raise RuntimeError(f"tool exited {status}: {stderr_path.read_text()}")


def tcp_test(output):
    announce("TCP test: capturing three separate clients and a 50-connection burst...")
    raw = output / "tcp.raw"
    err = output / "tcp.err"
    process = run_tool("tcp_tracker", 10, raw, err)
    time.sleep(2)
    if process.poll() is not None:
        finish_tool(process, err)
        raise RuntimeError("tcp_tracker exited before test traffic")

    client_pids = []
    client_code = (
        "import socket,sys\n"
        "for _ in range(int(sys.argv[2])):\n"
        "    with socket.create_connection(('127.0.0.1', int(sys.argv[1]))) as s:\n"
        "        s.sendall(b'ping')\n"
        "        assert s.recv(4) == b'pong'\n"
    )
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(128)
        port = server.getsockname()[1]
        for connections in (1, 1, 1, 50):
            client = subprocess.Popen([
                sys.executable, "-c", client_code, str(port), str(connections),
            ])
            client_pids.append(client.pid)
            for _ in range(connections):
                with server.accept()[0] as accepted:
                    if accepted.recv(4) != b"ping":
                        raise RuntimeError("TCP test payload was not received")
                    accepted.sendall(b"pong")
            if client.wait(timeout=3):
                raise RuntimeError("TCP client process failed")
            time.sleep(0.05)

    finish_tool(process, err)
    lines = [line for line in raw.read_text().splitlines()
             if "127.0.0.1" in line and f":{port}" in line]
    expected_connections = 53
    if len(lines) != 2 * expected_connections:
        raise RuntimeError(f"Expected {2 * expected_connections} loopback events, "
                           f"got {len(lines)}")
    observed_pids = {int(line.split()[0]) for line in lines}
    if not set(client_pids).issubset(observed_pids):
        raise RuntimeError(f"Missing client PIDs: {set(client_pids) - observed_pids}")
    server_pid = os.getpid()
    server_side_pids = sorted({int(line.split()[0]) for line in lines
                              if line.split()[2].endswith(f":{port}")})
    if server_side_pids != [server_pid]:
        raise RuntimeError(f"Server-side attribution was {server_side_pids}, "
                           f"expected {[server_pid]}")
    announce(f"TCP PASS: {len(lines)} events for {expected_connections} connections; "
             "outbound client and inbound server PIDs matched.")
    return {"port": port, "connections": expected_connections,
            "matching_events": len(lines),
            "client_pids": client_pids, "server_pid": server_pid,
            "server_side_reported_pids": server_side_pids,
            "sample": lines[0]}


def histogram_summary(path):
    text = path.read_text()
    rows = [(label.strip(), unit, int(count)) for label, unit, count in ROW.findall(text)]
    windows = text.count("Scheduler Run Queue Latency  (1s window")
    if not windows or not rows:
        raise RuntimeError(f"No scheduler histogram data in {path}")
    total = sum(count for _, _, count in rows)
    ms_plus = sum(count for _, unit, count in rows if unit in ("ms", "s"))
    nonzero = [(int(label) * {"us": 1, "ms": 1000, "s": 1000000}[unit]
                if label != "< 1" else 0, f"{label} {unit}")
               for label, unit, count in rows if count]
    return {
        "windows": windows,
        "events": total,
        "events_in_1ms_or_higher_display_buckets": ms_plus,
        "highest_nonzero_display_bucket": max(nonzero)[1] if nonzero else None,
    }


def scheduler_test(output, label, workers=None):
    announce(f"Scheduler test: {label} (10 seconds)...")
    raw = output / f"scheduler-{label}.raw"
    err = output / f"scheduler-{label}.err"
    process = None
    workers = workers or []
    try:
        process = run_tool("sched_lat", 10, raw, err)
        finish_tool(process, err)
    finally:
        for worker in workers:
            worker.terminate()
        for worker in workers:
            try:
                worker.wait(timeout=3)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait()
    (output / f"scheduler-{label}.txt").write_text(
        raw.read_text().replace("\x1b[2J\x1b[H", "\n--- next one-second window ---\n")
    )
    result = histogram_summary(raw)
    announce(f"{label}: {result['events']} events, "
             f"{result['events_in_1ms_or_higher_display_buckets']} in >=1 ms buckets "
             f"across {result['windows']} windows.")
    return result


def start_workers(cpu_count):
    busy = max(2, 2 * cpu_count)
    periodic = min(4, cpu_count)
    workers = []
    try:
        for _ in range(busy):
            workers.append(subprocess.Popen(["yes"], stdout=subprocess.DEVNULL))
        for _ in range(periodic):
            workers.append(subprocess.Popen(
                [sys.executable, "-c", "import time\nwhile True: time.sleep(0.01)"],
                stdout=subprocess.DEVNULL,
            ))
        time.sleep(1)
        return workers, busy, periodic
    except Exception:
        for worker in workers:
            worker.terminate()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    build()
    cpu_count = os.cpu_count() or 1
    results = {
        "run_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "kernel": os.uname().release,
        "architecture": os.uname().machine,
        "logical_cpus": cpu_count,
        "tcp": tcp_test(output),
        "scheduler_baseline": scheduler_test(output, "baseline"),
    }
    workers, busy, periodic = start_workers(cpu_count)
    results["contention_workload"] = {
        "busy_yes_processes": busy,
        "periodic_sleep_processes": periodic,
        "periodic_sleep_seconds": 0.01,
    }
    results["scheduler_contention"] = scheduler_test(output, "contention", workers)
    (output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    announce("Saved summary.json and raw tool output.")


if __name__ == "__main__":
    main()
