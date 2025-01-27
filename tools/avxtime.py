#!/usr/bin/env python
#
# avxtime   Summarize AVX-512 cputime per task as a histogram.
#           For Linux, uses BCC, eBPF.
#
# USAGE: avxtime [-h] [-T] [-m] [-C] [-P] [-c CPU] [-p PID] [interval] [count]
#
# Copyright (c) 2023 ByteDance Inc. All rights reserved.
#
# 29-Oct-2023   Zhiyong Ye <yezhiyong@bytedance.com>    Created this.

from __future__ import print_function
from bcc import BPF, utils
from time import sleep, strftime
import argparse

examples = """examples:
    avxtime              # summarize AVX-512 cputime as a histogram
    avxtime 1 10         # print 1 second summaries, 10 times
    avxtime -mT 1        # 1s summaries, milliseconds, and timestamps
    avxtime -C           # show each CPU separately
    avxtime -P           # show each PID separately
    avxtime -c 1         # trace CPU 1 only
    avxtime -p 185       # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Summarize AVX-512 cputime per task as a histogram.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-C", "--cpus", action="store_true",
    help="show each CPU separately")
parser.add_argument("-P", "--pids", action="store_true",
    help="print a histogram per process ID")
parser.add_argument("-c", "--cpu", type=int, help="trace this CPU only")
parser.add_argument("-p", "--pid", type=int, help="trace this PID only")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <asm/page_types.h>
#include <asm/fpu/types.h>

typedef struct pid_key {
    u64 id;
    u64 slot;
} pid_key_t;

typedef struct cpu_key {
    u64 id;
    u64 slot;
} cpu_key_t;

BPF_HASH(start, u32, u64, MAX_PID);
BPF_HASH(avxts, u32, u64, MAX_PID);
STORAGE
"""

bpf_text_kprobe = """
static inline int x86_fpu_regs_deactivated(struct fpu *fpu)
{
    u64 ts, ts_avx, *tsp, ts_avx_prev, delta;
    u32 tgid, cpu;

    bpf_probe_read_kernel(&ts_avx, sizeof(fpu->avx512_timestamp), &fpu->avx512_timestamp);
    if (ts_avx == 0)
        return 0;
    
    tgid = bpf_get_current_pid_tgid() >> 32;
    cpu = bpf_get_smp_processor_id();

    if (PID_FILTER)
        return 0;
    if (CPU_FILTER)
        return 0;

    tsp = avxts.lookup(&tgid);
    ts_avx_prev = tsp ? *tsp : 0;
    if (ts_avx == ts_avx_prev)
        return 0;
    
    avxts.update(&tgid, &ts_avx);

    ts = bpf_ktime_get_ns();
    tsp = start.lookup(&tgid);
    if (!tsp || ts < *tsp)
        return 0;

    delta = ts - *tsp;
    FACTOR
    STORE

    return 0;
}

int trace_finish_task_switch(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 tgid;
    u64 ts;

    tgid = bpf_get_current_pid_tgid() >> 32;

    if (PID_FILTER)
        return 0;

    ts = bpf_ktime_get_ns();
    start.update(&tgid, &ts);

    return 0;
}

int trace_switch_fpu_prepare(struct pt_regs *ctx, struct fpu *fpu, int cpu)
{
    return x86_fpu_regs_deactivated(fpu);
}

int trace_fpregs_deactivate(struct pt_regs *ctx, struct fpu *fpu)
{
    return x86_fpu_regs_deactivated(fpu);
}
"""

bpf_text_raw_tp = """
RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *next= (struct task_struct *)ctx->args[2];
    u32 tgid;
    u64 ts;

    bpf_probe_read_kernel(&tgid, sizeof(next->tgid), &next->tgid);

    if (PID_FILTER)
        return 0;

    ts = bpf_ktime_get_ns();
    start.update(&tgid, &ts);

    return 0;
}

RAW_TRACEPOINT_PROBE(x86_fpu_regs_deactivated)
{
    // TP_PROTO(struct fpu *fpu)
    struct fpu *fpu = (struct fpu *)ctx->args[0];
    u64 ts, ts_avx, *tsp, ts_avx_prev, delta;
    u32 tgid, cpu;

    bpf_probe_read_kernel(&ts_avx, sizeof(fpu->avx512_timestamp), &fpu->avx512_timestamp);
    if (ts_avx == 0)
        return 0;
    
    tgid = bpf_get_current_pid_tgid() >> 32;
    cpu = bpf_get_smp_processor_id();

    if (PID_FILTER)
        return 0;
    if (CPU_FILTER)
        return 0;

    tsp = avxts.lookup(&tgid);
    ts_avx_prev = tsp ? *tsp : 0;
    if (ts_avx == ts_avx_prev)
        return 0;
    
    avxts.update(&tgid, &ts_avx);

    ts = bpf_ktime_get_ns();
    tsp = start.lookup(&tgid);
    if (!tsp || ts < *tsp)
        return 0;

    delta = ts - *tsp;
    FACTOR
    STORE

    return 0;
}
"""

is_support_raw_tp = BPF.support_raw_tracepoint()
if is_support_raw_tp:
    bpf_text += bpf_text_raw_tp
else:
    bpf_text += bpf_text_kprobe

if args.pid:
    bpf_text = bpf_text.replace('PID_FILTER', 'tgid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('PID_FILTER', '0')

if args.cpu:
    bpf_text = bpf_text.replace('CPU_FILTER', 'cpu != %s' % args.cpu)
else:
    bpf_text = bpf_text.replace('CPU_FILTER', '0')

if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
else:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"

storage_str = ""
store_str = ""

if args.pids:
    section = "pid"
    storage_str += "BPF_HISTOGRAM(dist, pid_key_t, MAX_PID);"
    store_str += """
    pid_key_t key = {.id = tgid, .slot = bpf_log2l(delta)};
    dist.increment(key);
    """
elif args.cpus:
    section = "cpu"
    storage_str += "BPF_HISTOGRAM(dist, cpu_key_t, MAX_CPU);"
    store_str += """
    cpu_key_t key = {.id = cpu, .slot = bpf_log2l(delta)};
    dist.increment(key);
    """
else:
    section = ""
    storage_str += "BPF_HISTOGRAM(dist);"
    store_str += "dist.atomic_increment(bpf_log2l(delta));"

bpf_text = bpf_text.replace("STORAGE", storage_str)
bpf_text = bpf_text.replace("STORE", store_str)

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

max_pid = int(open("/proc/sys/kernel/pid_max").read())
num_cpus = len(utils.get_online_cpus())

b = BPF(text=bpf_text, cflags=["-DMAX_PID=%d" % max_pid, "-DMAX_CPU=%d" % num_cpus])
if not is_support_raw_tp:
    b.attach_kprobe(event="switch_fpu_prepare", fn_name="trace_switch_fpu_prepare")
    b.attach_kprobe(event="fpregs_deactivate", fn_name="trace_fpregs_deactivate")
    b.attach_kprobe(event_re="^finish_task_switch$|^finish_task_switch\.isra\.\d$",
                    fn_name="trace_finish_task_switch")

print("Tracing AVX-512 cputime... Hit Ctrl-C to end.")

exiting = 0 if args.interval else 1
dist = b.get_table("dist")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    def pid_to_comm(pid):
        try:
            comm = open("/proc/%d/comm" % pid, "r").read()
            return "%d %s" % (pid, comm)
        except IOError:
            return str(pid)

    if args.pids or args.pid:
        dist.print_log2_hist(label, section, section_print_fn=pid_to_comm)
    else:
        dist.print_log2_hist(label, section, section_print_fn=int)

    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()
