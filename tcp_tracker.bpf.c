// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TCP_ESTABLISHED 1
#define TCP_CLOSE       7
#define TASK_COMM_LEN   16

struct conn_info {
    __u64 start_ns;
    __u32 pid;
    char  comm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct event {
    __u32 pid;
    char  comm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 duration_ns;
};

/* expose event type in BTF so the skeleton header sees it */
struct event *unused_event __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct conn_info);
} conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MB */
} events SEC(".maps");

#define TCP_SYN_SENT    2

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    __u64 skaddr = (__u64)(unsigned long)ctx->skaddr;

    if (ctx->newstate == TCP_SYN_SENT) {
        /*
         * Fires in process context when connect() is called — the only
         * reliable place to capture the originating PID for outbound conns.
         */
        struct conn_info info = {};
        info.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&info.comm, sizeof(info.comm));
        __builtin_memcpy(&info.saddr, ctx->saddr, 4);
        __builtin_memcpy(&info.daddr, ctx->daddr, 4);
        info.sport = ctx->sport;
        info.dport = ctx->dport;
        bpf_map_update_elem(&conns, &skaddr, &info, BPF_ANY);

    } else if (ctx->newstate == TCP_ESTABLISHED) {
        struct conn_info *info = bpf_map_lookup_elem(&conns, &skaddr);
        if (info) {
            /* outbound: PID already set at SYN_SENT; fill in sport now
             * (kernel assigns the ephemeral port after connect() returns,
             * so SYN_SENT fires before it's set) */
            info->start_ns = bpf_ktime_get_ns();
            info->sport    = ctx->sport;
        } else {
            /* inbound (server-accepted): pid will be 0, track anyway */
            struct conn_info new_info = {};
            new_info.start_ns = bpf_ktime_get_ns();
            new_info.pid      = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&new_info.comm, sizeof(new_info.comm));
            __builtin_memcpy(&new_info.saddr, ctx->saddr, 4);
            __builtin_memcpy(&new_info.daddr, ctx->daddr, 4);
            new_info.sport = ctx->sport;
            new_info.dport = ctx->dport;
            bpf_map_update_elem(&conns, &skaddr, &new_info, BPF_ANY);
        }

    } else if (ctx->newstate == TCP_CLOSE) {
        struct conn_info *info = bpf_map_lookup_elem(&conns, &skaddr);
        if (!info)
            return 0;
        /* start_ns is only set at ESTABLISHED — if still 0 the handshake
         * never completed (e.g. connection refused / timed out), skip it */
        if (!info->start_ns) {
            bpf_map_delete_elem(&conns, &skaddr);
            return 0;
        }

        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = info->pid;
            __builtin_memcpy(e->comm, info->comm, sizeof(e->comm));
            e->saddr       = info->saddr;
            e->daddr       = info->daddr;
            e->sport       = info->sport;
            e->dport       = info->dport;
            e->duration_ns = bpf_ktime_get_ns() - info->start_ns;
            bpf_ringbuf_submit(e, 0);
        }
        bpf_map_delete_elem(&conns, &skaddr);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
