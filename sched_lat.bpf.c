// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_BUCKETS 32

/* pid → timestamp when it became runnable */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} wakeup_ts SEC(".maps");

/*
 * Log2 histogram: index n holds count of latencies in [2^n µs, 2^(n+1) µs).
 * Bucket 0 catches everything under ~2 µs.
 * Userspace reads and zeroes this every second.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BUCKETS);
    __type(key, u32);
    __type(value, u64);
} latency_hist SEC(".maps");

static __always_inline void record_wakeup(u32 pid)
{
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_ts, &pid, &ts, BPF_ANY);
}

static __always_inline void record_latency(u32 pid)
{
    u64 *tsp = bpf_map_lookup_elem(&wakeup_ts, &pid);
    if (!tsp)
        return;

    u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&wakeup_ts, &pid);

    /* convert to µs, then find log2 bucket */
    u64 us = delta_ns / 1000;
    u32 bucket = 0;
    while (us > 1 && bucket < MAX_BUCKETS - 1) {
        us >>= 1;
        bucket++;
    }

    u64 *count = bpf_map_lookup_elem(&latency_hist, &bucket);
    if (count)
        __sync_fetch_and_add(count, 1);
}

SEC("tracepoint/sched/sched_wakeup")
int handle_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    record_wakeup(ctx->pid);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup_new")
int handle_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
    record_wakeup(ctx->pid);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
    record_latency(ctx->next_pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
