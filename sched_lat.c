#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "sched_lat.skel.h"

#define MAX_BUCKETS 32
#define BAR_WIDTH   40

static volatile int running = 1;

static void sig_handler(int sig) { (void)sig; running = 0; }

/* Label for bucket n: the lower bound of its µs range. */
static void bucket_label(int n, char *buf, size_t len)
{
    if (n == 0) {
        snprintf(buf, len, "  < 1 us");
        return;
    }
    unsigned long us = 1UL << n; /* 2^n µs */
    if (us < 1000)
        snprintf(buf, len, "%4lu us ", us);
    else if (us < 1000000)
        snprintf(buf, len, "%4lu ms ", us / 1000);
    else
        snprintf(buf, len, "%4lu s  ", us / 1000000);
}

static void print_histogram(int hist_fd)
{
    uint64_t counts[MAX_BUCKETS] = {};
    uint64_t max_count = 0;

    /* read all buckets */
    for (uint32_t i = 0; i < MAX_BUCKETS; i++) {
        bpf_map_lookup_elem(hist_fd, &i, &counts[i]);
        if (counts[i] > max_count)
            max_count = counts[i];
    }

    /* zero the histogram so next interval starts fresh */
    uint64_t zero = 0;
    for (uint32_t i = 0; i < MAX_BUCKETS; i++)
        bpf_map_update_elem(hist_fd, &i, &zero, BPF_ANY);

    /* clear screen and move cursor to top */
    printf("\033[2J\033[H");
    printf("Scheduler Run Queue Latency  (1s window, Ctrl-C to stop)\n");
    printf("==========================================================\n");
    printf("%-10s %10s   %-*s\n", "bucket", "count", BAR_WIDTH, "distribution");

    for (int i = 0; i < MAX_BUCKETS; i++) {
        if (i > 0 && counts[i] == 0) {
            /* find last non-zero bucket to avoid trailing empty rows */
            int any_left = 0;
            for (int j = i + 1; j < MAX_BUCKETS; j++)
                if (counts[j]) { any_left = 1; break; }
            if (!any_left)
                break;
        }

        char label[16];
        bucket_label(i, label, sizeof(label));

        int bar_len = (max_count > 0)
            ? (int)((double)counts[i] / max_count * BAR_WIDTH)
            : 0;

        /* build bar: bar_len block chars, rest spaces, total BAR_WIDTH display cols */
        char bar[BAR_WIDTH * 3 + BAR_WIDTH + 1];
        int pos = 0;
        for (int j = 0; j < bar_len; j++) {
            bar[pos++] = (char)0xe2; /* UTF-8 for █ */
            bar[pos++] = (char)0x96;
            bar[pos++] = (char)0x88;
        }
        for (int j = bar_len; j < BAR_WIDTH; j++)
            bar[pos++] = ' ';
        bar[pos] = '\0';

        printf("%s : %10llu   |%s|\n",
               label, (unsigned long long)counts[i], bar);
    }
    fflush(stdout);
}

int main(void)
{
    struct sched_lat_bpf *skel;
    int err;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = sched_lat_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    err = sched_lat_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    printf("Attached. Collecting scheduler latency data...\n");
    sleep(1);

    int hist_fd = bpf_map__fd(skel->maps.latency_hist);

    while (running) {
        sleep(1);
        print_histogram(hist_fd);
    }

    printf("\nDone.\n");

cleanup:
    sched_lat_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
