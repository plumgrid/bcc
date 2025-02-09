// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/* 
 * schedtimes Trace process run/sleep/block/queue time
 * Copyright (c) 2022 Tencent.
 *
 * Based on schedtime.stp from systemtap 
 * 20-Dec-2022 Curu Wong created this.
 */
#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "schedtimes.h"
#include "schedtimes.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

#define OUTPUT_ROWS_LIMIT MAX_ENTRIES
enum SORT {
    ALL,
    RUN,
    SLEEP,
    BLOCK,
    QUEUE,
};

struct env {
    pid_t pid;
    pid_t tid;
    pid_t ppid;
    bool verbose;
    bool nosleep;
} env = {
    .verbose = false,
    .nosleep = false,
};

static volatile sig_atomic_t exiting = 0;

static bool clear_screen = true;
static int output_rows = 20;
static int sort_by = ALL;
static int interval = 1;
static int count = 99999999;

const char *argp_program_version = "schedtimes 0.1";
const char *argp_program_bug_address =
    "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Profile threads and show their run/sleep/block/queue times\n"
"\n"
"USAGE: schedtimes [-h] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    schedtimes -p 185   # trace for PID 185 only\n"
"    schedtimes -t 185   # trace for TID 185 only\n"
"    schedtimes -c 185   # trace children of PID 185 only\n"
"    schedtimes 5 10 # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
    { "noclear", 'C', NULL, 0, "Don't clear the screen" },
    { "sort", 's', "SORT", 0, "Sort columns, default all [all, run, sleep, block, queue]" },
    { "pid", 'p', "PID", 0, "Trace this process PID only"},
    { "tid", 't', "TID", 0, "Trace this thread TID only"},
    { "ppid", 'c', "PPID", 0, "Trace children of PPID only"},
    { "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20"},
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "nosleep", 'S', NULL, 0, "Don't show sleep time" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    int pid;
    int rows;
    static int pos_args;

    switch (key) {
    case 'C':
        clear_screen = false;
        break;
    case 'S':
        env.nosleep = true;
        break;
    case 's':
        if (!strcmp(arg, "all")) {
            sort_by = ALL;
        } else if (!strcmp(arg, "run")) {
            sort_by = RUN;
        } else if (!strcmp(arg, "sleep")) {
            sort_by = SLEEP;
        } else if (!strcmp(arg, "block")) {
            sort_by = BLOCK;
        } else if (!strcmp(arg, "queue")) {
            sort_by = QUEUE;
        } else {
            fprintf(stderr, "Invalid sort method: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'p':
        errno = 0;
        pid = strtol(arg, NULL, 10);
        if (errno || pid <= 0) {
            fprintf(stderr, "Invalid PID: %s\n", arg);
            argp_usage(state);
        }
        env.pid = pid;
        break;
    case 'r':
        errno = 0;
        rows = strtol(arg, NULL, 10);
        if (errno || rows <= 0) {
            fprintf(stderr, "Invalid rows: %s\n", arg);
            argp_usage(state);
        }
        output_rows = rows;
        if(output_rows > OUTPUT_ROWS_LIMIT)
            output_rows = OUTPUT_ROWS_LIMIT;
        break;
    case 't':
        errno = 0;
        pid = strtol(arg, NULL, 10);
        if (errno || pid <= 0) {
            fprintf(stderr, "Invalid TID: %s\n", arg);
            argp_usage(state);
        }
        env.tid = pid;
        break;
    case 'c':
        errno = 0;
        pid = strtol(arg, NULL, 10);
        if (errno || pid <= 0) {
            fprintf(stderr, "Invalid PPID: %s\n", arg);
            argp_usage(state);
        }
        env.ppid = pid;
        break;
    case ARGP_KEY_ARG:
        errno = 0;
        if (pos_args == 0) {
            interval = strtol(arg, NULL, 10);
            if (errno || interval <= 0) {
                fprintf(stderr, "invalid interval (in s)\n");
                argp_usage(state);
            }
        } else if(pos_args == 1) {
            count = strtol(arg, NULL, 10);
            if (errno || count <= 0){
                fprintf(stderr, "invalid count\n");
                argp_usage(state);
            }
        }
        else {
            fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
            argp_usage(state);
        }
        pos_args++;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
    exiting = 1;
}

static int sort_column(const void *obj1, const void *obj2)
{
    __u64 s1_val, s2_val;
    struct sched_times_t *s1 = (struct sched_times_t*)obj1;
    struct sched_times_t *s2 = (struct sched_times_t*)obj2;


    switch (sort_by) {
    case RUN:
        s2_val = s2->run_time;
        s1_val = s1->run_time;
        break;
    case SLEEP:
        s2_val = s2->sleep_time;
        s1_val = s1->sleep_time;
        break;
    case BLOCK:
        s2_val = s2->block_time;
        s1_val = s1->block_time;
        break;
    case QUEUE:
        s2_val = s2->queue_time;
        s1_val = s1->queue_time;
        break;
    default:
        s2_val = s2->run_time + s2->block_time + s2->queue_time;
        s1_val = s1->run_time + s1->block_time + s1->queue_time;
        if(!env.nosleep){
            s2_val += s2->sleep_time;
            s1_val += s1->sleep_time;
        }
        break;
    }

    //workaround int overflow for u64
    if(s2_val > s1_val){
        return 1;
    }else{
        return s2_val < s1_val ? -1 : 0;
    }
}

static int print_map(struct schedtimes_bpf *obj)
{
    __u32 lookup_key = -2, next_key;
    int schedtimes_fd;
    struct sched_times_t val;
    time_t t;
    struct tm *tm;
    char ts[15];

    static struct sched_times_t datas[OUTPUT_ROWS_LIMIT];
    static __u32 keys[OUTPUT_ROWS_LIMIT];
    __u32 key_size = sizeof(__u32);
    __u32 value_size = sizeof(datas[0]);
    __u32 i, rows=OUTPUT_ROWS_LIMIT;
    int err=0;
    __u64 total_time;

    schedtimes_fd = bpf_map__fd(obj->maps.sched_times);

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    printf("%s\n", ts);
    if(env.nosleep){
        printf("%-16s %-7s %-10s %-10s %-10s %s\n",
                "COMM", "PID", "RUN(us)", "BLOCK(us)", "QUEUE(us)", "TOTAL(us)");
    }else{
        printf("%-16s %-7s %-10s %-10s %-10s %-10s %s\n",
                "COMM", "PID", "RUN(us)", "SLEEP(us)", "BLOCK(us)", "QUEUE(us)", "TOTAL(us)");
    }

    if(dump_hash(schedtimes_fd, keys, key_size, datas, value_size, &rows, &lookup_key)){
        fprintf(stderr, "failed to dump_hash: %d\n", err);
    }
    //copy key to datas for qsort
    for(i=0; i < rows; i++){
        datas[i].key = keys[i];
    }
    qsort(datas, rows, sizeof(struct sched_times_t), sort_column);
    rows = rows < output_rows ? rows : output_rows;
    for(i=0; i<rows; i++){
        val = datas[i];
        total_time =  val.run_time + val.block_time +val.queue_time;
        if(!env.nosleep){
            total_time += val.sleep_time;
        }
        if(env.nosleep){
            printf("%-16s %-7d %-10llu %-10llu %-10llu %-10llu\n",
                val.comm, val.key,
                val.run_time/1000, val.block_time/1000, val.queue_time/1000,
                total_time/1000);
        }else{
            printf("%-16s %-7d %-10llu %-10llu %-10llu %-10llu %-10llu\n",
                val.comm, val.key,
                val.run_time/1000, val.sleep_time/1000, val.block_time/1000, val.queue_time/1000,
                total_time/1000);
        }
    }
    printf("\n");

    //clear map
    lookup_key = -2;
    while(1){
        err = bpf_map_get_next_key(schedtimes_fd, &lookup_key, &next_key);
        if(err){
            if (errno == ENOENT){
                err = 0;
                break;
            }
            fprintf(stderr, "bpf_map_get_next_key failed: %s\n", strerror(errno));
            return err;
        }
        err = bpf_map_delete_elem(schedtimes_fd, &next_key);
        if(err){
            fprintf(stderr, "bpf_map_delete_elem failed: %s\n", strerror(errno));
            return err;
        }
        lookup_key = next_key;
    }
    return err;
}

int main(int argc, char **argv)
{
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    struct schedtimes_bpf *obj;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = schedtimes_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    obj->rodata->target_pid = env.tid;
    obj->rodata->target_tgid = env.pid;
    obj->rodata->target_ppid = env.ppid;
    obj->rodata->no_sleeptime = env.nosleep;

    if (probe_tp_btf("sched_wakeup")) {
        bpf_program__set_autoload(obj->progs.handle_sched_wakeup, false);
        bpf_program__set_autoload(obj->progs.handle_sched_wakeup_new, false);
        bpf_program__set_autoload(obj->progs.handle_sched_switch, false);
    } else {
        bpf_program__set_autoload(obj->progs.sched_wakeup, false);
        bpf_program__set_autoload(obj->progs.sched_wakeup_new, false);
        bpf_program__set_autoload(obj->progs.sched_switch, false);
    }

    err = schedtimes_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = schedtimes_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    printf("Tracing sched times\n");
    while(1) {
        sleep(interval);
        if(clear_screen) {
            err = system("clear");
            if(err)
                goto cleanup;
        }
        print_map(obj);
        count--;
        if(exiting || !count)
            goto cleanup;
    }

cleanup:
    schedtimes_bpf__destroy(obj);
    return err != 0;
}

