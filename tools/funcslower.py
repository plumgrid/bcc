#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# funcslower  Trace slow kernel or user function calls.
#             For Linux, uses BCC, eBPF.
#
# USAGE: funcslower [-h] [-p PID] [-m MIN_MS] [-u MIN_US] [-a ARGUMENTS]
#                   [-T] [-t] [-v] function [function ...]
#
# WARNING: This tool traces function calls by instrumenting the entry and
# return from each function. For commonly-invoked functions like memory allocs
# or file writes, this can be extremely expensive. Mind the overhead.
#
# NOTE: This tool cannot trace nested functions in the same invocation
# due to instrumentation specifics, only innermost calls will be visible.
#
# By default, a minimum millisecond threshold of 1 is used.
#
# Copyright 2017, Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 30-Mar-2017   Sasha Goldshtein    Created this.

from __future__ import print_function
from bcc import BPF
import argparse
import time

examples = """examples:
  ./funcslower vfs_write        # trace vfs_write calls slower than 1ms
  ./funcslower -m 10 vfs_write  # same, but slower than 10ms
  ./funcslower -u 10 c:open     # trace open calls slower than 10us
  ./funcslower -p 135 c:open    # trace pid 135 only
  ./funcslower c:malloc c:free  # trace both malloc and free slower than 1ms
  ./funcslower -a 2 c:open      # show first two arguments to open
  ./funcslower -UK -m 10 c:open # Show user and kernel stack frame of open calls slower than 10ms
  ./funcslower -f -UK c:open    # Output in folded format for flame graphs
"""
parser = argparse.ArgumentParser(
    description="Trace slow kernel or user function calls.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, metavar="PID", dest="tgid",
    help="trace this PID only")
parser.add_argument("-m", "--min-ms", type=float, dest="min_ms",
    help="minimum duration to trace (ms)")
parser.add_argument("-u", "--min-us", type=float, dest="min_us",
    help="minimum duration to trace (us)")
parser.add_argument("-a", "--arguments", type=int,
    help="print this many entry arguments, as hex")
parser.add_argument("-T", "--time", action="store_true",
    help="show HH:MM:SS timestamp")
parser.add_argument("-t", "--timestamp", action="store_true",
    help="show timestamp in seconds at us resolution")
parser.add_argument("-v", "--verbose", action="store_true",
    help="print the BPF program for debugging purposes")
parser.add_argument(metavar="function", nargs="+", dest="functions",
    help="function(s) to trace")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format, one line per stack (for flame graphs)")
parser.add_argument("-U", "--user-stack",
  action="store_true", help="output user stack trace")
parser.add_argument("-K", "--kernel-stack",
  action="store_true", help="output kernel stack trace")

args = parser.parse_args()
# fractions are allowed, but rounded to an integer nanosecond
if args.min_ms:
    duration_ns = int(args.min_ms * 1000000)
elif args.min_us:
    duration_ns = int(args.min_us * 1000)
else:
    duration_ns = 1000000   # default to 1ms

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>    // for TASK_COMM_LEN

struct entry_t {
    u64 start_ns;
#ifdef GRAB_ARGS
#ifndef __s390x__
    u64 args[6];
#else
    u64 args[5];
#endif
#endif
#ifdef USER_STACKS
    int user_stack_id;
#endif
#ifdef KERNEL_STACKS
    int kernel_stack_id;
    u64 kernel_ip;
#endif
};

struct key_t {
    u64 tgid_pid;
    u64 id;
};

struct data_t {
    u64 id;
    u64 tgid_pid;
    u64 start_ns;
    u64 duration_ns;
    u64 retval;
    char comm[TASK_COMM_LEN];
#ifdef GRAB_ARGS
#ifndef __s390x__
    u64 args[6];
#else
    u64 args[5];
#endif
#endif
#ifdef USER_STACKS
    int user_stack_id;
#endif
#ifdef KERNEL_STACKS
    int kernel_stack_id;
    u64 kernel_ip;
#endif
};

BPF_HASH(entryinfo, struct key_t, struct entry_t);
BPF_PERF_OUTPUT(events);

#if defined(USER_STACKS) || defined(KERNEL_STACKS)
BPF_STACK_TRACE(stacks, 2048);
#endif

static int trace_entry(struct pt_regs *ctx, int id)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;
    if (TGID_FILTER)
        return 0;

    u32 pid = tgid_pid;

    struct key_t key = {};
    key.tgid_pid = tgid_pid;
    key.id = id;

    struct entry_t entry = {};
    entry.start_ns = bpf_ktime_get_ns();
#ifdef GRAB_ARGS
    entry.args[0] = PT_REGS_PARM1(ctx);
    entry.args[1] = PT_REGS_PARM2(ctx);
    entry.args[2] = PT_REGS_PARM3(ctx);
    entry.args[3] = PT_REGS_PARM4(ctx);
    entry.args[4] = PT_REGS_PARM5(ctx);
#ifndef __s390x__
    entry.args[5] = PT_REGS_PARM6(ctx);
#endif
#endif

#ifdef USER_STACKS
    entry.user_stack_id = stacks.get_stackid(ctx, BPF_F_USER_STACK);
#endif

#ifdef KERNEL_STACKS
    entry.kernel_stack_id = stacks.get_stackid(ctx, 0);

    if (entry.kernel_stack_id >= 0) {
        u64 ip = PT_REGS_IP(ctx);
        u64 page_offset;

        // if ip isn't sane, leave key ips as zero for later checking
#if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
        // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
        page_offset = __PAGE_OFFSET_BASE;
#elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
        // x64, 4.17, and later
#if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
        page_offset = __PAGE_OFFSET_BASE_L5;
#else
        page_offset = __PAGE_OFFSET_BASE_L4;
#endif
#else
        // earlier x86_64 kernels, e.g., 4.6, comes here
        // arm64, s390, powerpc, x86_32
        page_offset = PAGE_OFFSET;
#endif

        if (ip > page_offset) {
            entry.kernel_ip = ip;
        }
    }
#endif

    entryinfo.update(&key, &entry);

    return 0;
}

static int trace_return(struct pt_regs *ctx, int id)
{
    struct entry_t *entryp;
    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct key_t key = {};
    key.tgid_pid = tgid_pid;
    key.id = id;

    entryp = entryinfo.lookup(&key);
    if (entryp == 0) {
        return 0;
    }

    u64 delta_ns = bpf_ktime_get_ns() - entryp->start_ns;
    entryinfo.delete(&key);

    if (delta_ns < DURATION_NS)
        return 0;

    struct data_t data = {};
    data.id = id;
    data.tgid_pid = tgid_pid;
    data.start_ns = entryp->start_ns;
    data.duration_ns = delta_ns;
    data.retval = PT_REGS_RC(ctx);

#ifdef USER_STACKS
    data.user_stack_id = entryp->user_stack_id;
#endif

#ifdef KERNEL_STACKS
    data.kernel_stack_id = entryp->kernel_stack_id;
    data.kernel_ip = entryp->kernel_ip;
#endif

#ifdef GRAB_ARGS
    bpf_probe_read_kernel(&data.args[0], sizeof(data.args), entryp->args);
#endif
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

bpf_text = bpf_text.replace('DURATION_NS', str(duration_ns))
if args.arguments:
    bpf_text = "#define GRAB_ARGS\n" + bpf_text
if args.user_stack:
    bpf_text = "#define USER_STACKS\n" + bpf_text
if args.kernel_stack:
    bpf_text = "#define KERNEL_STACKS\n" + bpf_text
if args.tgid:
    bpf_text = bpf_text.replace('TGID_FILTER', 'tgid != %d' % args.tgid)
else:
    bpf_text = bpf_text.replace('TGID_FILTER', '0')

for i in range(len(args.functions)):
    bpf_text += """
int trace_%d(struct pt_regs *ctx) {
    return trace_entry(ctx, %d);
}
int rtrace_%d(struct pt_regs *ctx) {
    return trace_return(ctx, %d);
}
""" % (i, i, i, i)

if args.verbose or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

b = BPF(text=bpf_text)

for i, function in enumerate(args.functions):
    if ":" in function:
        library, func = function.split(":")
        b.attach_uprobe(name=library, sym=func, fn_name="trace_%d" % i)
        b.attach_uretprobe(name=library, sym=func, fn_name="rtrace_%d" % i)
    else:
        b.attach_kprobe(event=function, fn_name="trace_%d" % i)
        b.attach_kretprobe(event=function, fn_name="rtrace_%d" % i)

time_designator = "us" if args.min_us else "ms"
time_value = args.min_us or args.min_ms or 1
time_multiplier = 1000 if args.min_us else 1000000
time_col = args.time or args.timestamp

# Do not print header when folded
if not args.folded:
    print("Tracing function calls slower than %g %s... Ctrl+C to quit." %
          (time_value, time_designator))
    print((("%-10s " % "TIME" if time_col else "") + "%-14s %-6s %7s %16s %s") %
        ("COMM", "PID", "LAT(%s)" % time_designator, "RVAL",
        "FUNC" + (" ARGS" if args.arguments else "")))

earliest_ts = 0

def time_str(event):
    if args.time:
        return "%-10s " % time.strftime("%H:%M:%S")
    if args.timestamp:
        global earliest_ts
        if earliest_ts == 0:
            earliest_ts = event.start_ns
        return "%-10.6f " % ((event.start_ns - earliest_ts) / 1000000000.0)
    return ""

def args_str(event):
    if not args.arguments:
        return ""
    return str.join(" ", ["0x%x" % arg for arg in event.args[:args.arguments]])

def print_stack(event):
    user_stack = []
    stack_traces = b.get_table("stacks")

    if args.user_stack and event.user_stack_id > 0:
        user_stack = stack_traces.walk(event.user_stack_id)

    kernel_stack = []
    if args.kernel_stack and event.kernel_stack_id > 0:
        kernel_tmp = stack_traces.walk(event.kernel_stack_id)

        # fix kernel stack
        for addr in kernel_tmp:
            kernel_stack.append(addr)

    do_delimiter = user_stack and kernel_stack

    if args.folded:
        # print folded stack output
        user_stack = list(user_stack)
        kernel_stack = list(kernel_stack)
        line = [event.comm] + \
            [b.sym(addr, event.tgid_pid) for addr in reversed(user_stack)] + \
            (do_delimiter and ["-"] or []) + \
            [b.ksym(addr) for addr in reversed(kernel_stack)]
        print("%s %d" % (b';'.join(line).decode('utf-8', 'replace'), 1))
    else:
        # print default multi-line stack output.
        for addr in kernel_stack:
            print("    %s" % b.ksym(addr).decode('utf-8', 'replace'))
        for addr in user_stack:
            print("    %s" % b.sym(addr, event.tgid_pid).decode('utf-8', 'replace'))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    ts = float(event.duration_ns) / time_multiplier
    if not args.folded:
        print((time_str(event) + "%-14.14s %-6s %7.2f %16x %s %s") %
            (event.comm.decode('utf-8', 'replace'), event.tgid_pid >> 32,
             ts, event.retval, args.functions[event.id], args_str(event)))
    if args.user_stack or args.kernel_stack:
        print_stack(event)

b["events"].open_perf_buffer(print_event, page_cnt=64)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
