#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include "tcp_tracker.skel.h"

#define TASK_COMM_LEN 16

struct event {
    __u32 pid;
    char  comm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 duration_ns;
};

static volatile int running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    (void)len;
    struct event *e = data;

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    struct in_addr sa = { .s_addr = e->saddr };
    struct in_addr da = { .s_addr = e->daddr };
    inet_ntop(AF_INET, &sa, src, sizeof(src));
    inet_ntop(AF_INET, &da, dst, sizeof(dst));

    char src_port[24], dst_port[24];
    snprintf(src_port, sizeof(src_port), "%s:%u", src, e->sport);
    snprintf(dst_port, sizeof(dst_port), "%s:%u", dst, e->dport);

    double ms = e->duration_ns / 1e6;
    printf("%-7u %-16s %-24s %-24s %.2f ms\n",
           e->pid, e->comm, src_port, dst_port, ms);

    return 0;
}

int main(void)
{
    struct tcp_tracker_bpf *skel;
    struct ring_buffer *rb;
    int err;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = tcp_tracker_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    err = tcp_tracker_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("%-7s %-16s %-24s %-24s %s\n",
           "PID", "COMM", "SRC", "DST", "DURATION");
    printf("%-7s %-16s %-24s %-24s %s\n",
           "-------", "----------------", "------------------------",
           "------------------------", "----------");

    while (running) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring buffer poll error: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
cleanup:
    tcp_tracker_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
