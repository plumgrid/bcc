#!/usr/bin/python
#
# offwaketime   Summarize blocked time by kernel off-CPU stack + waker stack
#               For Linux, uses BCC, eBPF.
#
# USAGE: offwaketime [-h] [-p PID | -u | -k] [-U | -K] [-f] [duration]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Jan-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep
import argparse
import signal
import errno
from sys import stderr

# arg validation
def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

# arguments
examples = """examples:
    ./offwaketime             # trace off-CPU + waker stack time until Ctrl-C
    ./offwaketime 5           # trace for 5 seconds only
    ./offwaketime -f 5        # 5 seconds, and output in folded format
    ./offwaketime -m 1000     # trace only events that last more than 1000 usec
    ./offwaketime -M 9000     # trace only events that last less than 9000 usec
    ./offwaketime -p 185      # only trace threads for PID 185
    ./offwaketime -t 188      # only trace thread 188
    ./offwaketime -u          # only trace user threads (no kernel)
    ./offwaketime -k          # only trace kernel threads (no user)
    ./offwaketime -U          # only show user space stacks (no kernel)
    ./offwaketime -K          # only show kernel space stacks (no user)
"""
parser = argparse.ArgumentParser(
    description="Summarize blocked time by kernel stack trace + waker stack",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
thread_group = parser.add_mutually_exclusive_group()
# Note: this script provides --pid and --tid flags but their arguments are
# referred to internally using kernel nomenclature: TGID and PID.
thread_group.add_argument("-p", "--pid", metavar="PID", dest="tgid",
    help="trace this PID only", type=positive_int)
thread_group.add_argument("-t", "--tid", metavar="TID", dest="pid",
    help="trace this TID only", type=positive_int)
thread_group.add_argument("-u", "--user-threads-only", action="store_true",
    help="user threads only (no kernel threads)")
thread_group.add_argument("-k", "--kernel-threads-only", action="store_true",
    help="kernel threads only (no user threads)")
stack_group = parser.add_mutually_exclusive_group()
stack_group.add_argument("-U", "--user-stacks-only", action="store_true",
    help="show stacks from user space only (no kernel space stacks)")
stack_group.add_argument("-K", "--kernel-stacks-only", action="store_true",
    help="show stacks from kernel space only (no user space stacks)")
parser.add_argument("-d", "--delimited", action="store_true",
    help="insert delimiter between kernel/user stacks")
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format")
parser.add_argument("--stack-storage-size", default=1024,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and "
         "displayed (default 1024)")
parser.add_argument("duration", nargs="?", default=99999999,
    type=positive_nonzero_int,
    help="duration of trace, in seconds")
parser.add_argument("-m", "--min-block-time", default=1,
    type=positive_nonzero_int,
    help="the amount of time in microseconds over which we " +
         "store traces (default 1)")
parser.add_argument("-M", "--max-block-time", default=(1 << 64) - 1,
    type=positive_nonzero_int,
    help="the amount of time in microseconds under which we " +
         "store traces (default U64_MAX)")
args = parser.parse_args()
folded = args.folded
duration = int(args.duration)

# signal handler
def signal_ignore(signal, frame):
    print()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MINBLOCK_US    MINBLOCK_US_VALUEULL
#define MAXBLOCK_US    MAXBLOCK_US_VALUEULL

struct key_t {
    char waker[TASK_COMM_LEN];
    char target[TASK_COMM_LEN];
    int w_k_stack_id;
    int w_u_stack_id;
    int t_k_stack_id;
    int t_u_stack_id;
    u32 t_pid;
    u32 w_pid;
    u32 tgid;
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
struct wokeby_t {
    char name[TASK_COMM_LEN];
    int k_stack_id;
    int u_stack_id;
    int w_pid;
};
BPF_HASH(wokeby, u32, struct wokeby_t);

BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE)

int waker(struct pt_regs *ctx, struct task_struct *p) {
    u32 pid = p->pid;
    u32 tgid = p->tgid;

    if (!(THREAD_FILTER)) {
        return 0;
    }

    struct wokeby_t woke = {};
    bpf_get_current_comm(&woke.name, sizeof(woke.name));

    woke.k_stack_id = KERNEL_STACK_GET;
    woke.u_stack_id = USER_STACK_GET;
    woke.w_pid = pid;
    wokeby.update(&pid, &woke);
    return 0;
}

int oncpu(struct pt_regs *ctx, struct task_struct *p) {
    u32 pid = p->pid, t_pid=pid;
    u32 tgid = p->tgid;
    u64 ts, *tsp;

    // record previous thread sleep time
    if (THREAD_FILTER) {
        ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }

    // calculate current thread's delta time
    pid = bpf_get_current_pid_tgid();
    tgid = bpf_get_current_pid_tgid() >> 32;
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }
    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);
    delta = delta / 1000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
        return 0;
    }

    // create map key
    u64 zero = 0, *val;
    struct key_t key = {};
    struct wokeby_t *woke;
    bpf_get_current_comm(&key.target, sizeof(key.target));

    key.t_k_stack_id = KERNEL_STACK_GET;
    key.t_u_stack_id = USER_STACK_GET;
    key.t_pid = t_pid;

    woke = wokeby.lookup(&pid);
    if (woke) {
        key.w_k_stack_id = woke->k_stack_id;
        key.w_u_stack_id = woke->u_stack_id;
        key.w_pid = woke->w_pid;
        key.tgid = tgid;
        __builtin_memcpy(&key.waker, woke->name, TASK_COMM_LEN);
        wokeby.delete(&pid);
    }

    val = counts.lookup_or_init(&key, &zero);
    (*val) += delta;
    return 0;
}
"""

# set thread filter
thread_context = ""
if args.tgid is not None:
    thread_context = "PID %d" % args.tgid
    thread_filter = 'tgid == %d' % args.tgid
elif args.pid is not None:
    thread_context = "TID %d" % args.pid
    thread_filter = 'pid == %d' % args.pid
elif args.user_threads_only:
    thread_context = "user threads"
    thread_filter = '!(p->flags & PF_KTHREAD)'
elif args.kernel_threads_only:
    thread_context = "kernel threads"
    thread_filter = 'p->flags & PF_KTHREAD'
else:
    thread_context = "all threads"
    thread_filter = '1'
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)

# set stack storage size
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))
bpf_text = bpf_text.replace('MINBLOCK_US_VALUE', str(args.min_block_time))
bpf_text = bpf_text.replace('MAXBLOCK_US_VALUE', str(args.max_block_time))

# handle stack args
kernel_stack_get = "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID)"
user_stack_get = \
    "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID | BPF_F_USER_STACK)"
stack_context = ""
if args.user_stacks_only:
    stack_context = "user"
    kernel_stack_get = "-1"
elif args.kernel_stacks_only:
    stack_context = "kernel"
    user_stack_get = "-1"
else:
    stack_context = "user + kernel"
bpf_text = bpf_text.replace('USER_STACK_GET', user_stack_get)
bpf_text = bpf_text.replace('KERNEL_STACK_GET', kernel_stack_get)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="finish_task_switch", fn_name="oncpu")
b.attach_kprobe(event="try_to_wake_up", fn_name="waker")
matched = b.num_open_kprobes()
if matched == 0:
    print("0 functions traced. Exiting.")
    exit()

# header
if not folded:
    print("Tracing blocked time (us) by %s off-CPU and waker stack" %
        stack_context, end="")
    if duration < 99999999:
        print(" for %d secs." % duration)
    else:
        print("... Hit Ctrl-C to end.")

# as cleanup can take many seconds, trap Ctrl-C:
# print a newline for folded output on Ctrl-C
signal.signal(signal.SIGINT, signal_ignore)

sleep(duration)

if not folded:
    print()

missing_stacks = 0
has_enomem = False
counts = b.get_table("counts")
stack_traces = b.get_table("stack_traces")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    # handle get_stackid errors
    # check for an ENOMEM error
    if k.w_k_stack_id == -errno.ENOMEM or \
       k.t_k_stack_id == -errno.ENOMEM or \
       k.w_u_stack_id == -errno.ENOMEM or \
       k.t_u_stack_id == -errno.ENOMEM:
        missing_stacks += 1
        continue

    waker_user_stack = [] if k.w_u_stack_id < 1 else \
        reversed(list(stack_traces.walk(k.w_u_stack_id))[1:])
    waker_kernel_stack = [] if k.w_k_stack_id < 1 else \
        reversed(list(stack_traces.walk(k.w_k_stack_id))[1:])
    target_user_stack = [] if k.t_u_stack_id < 1 else \
        stack_traces.walk(k.t_u_stack_id)
    target_kernel_stack = [] if k.t_k_stack_id < 1 else \
        stack_traces.walk(k.t_k_stack_id)

    if folded:
        # print folded stack output
        line = \
            [k.target] + \
            [b.sym(addr, k.tgid)
                for addr in reversed(list(target_user_stack)[1:])] + \
            (["-"] if args.delimited else [""]) + \
            [b.ksym(addr)
                for addr in reversed(list(target_kernel_stack)[1:])] + \
            ["--"] + \
            [b.ksym(addr)
                for addr in reversed(list(waker_kernel_stack))] + \
            (["-"] if args.delimited else [""]) + \
            [b.sym(addr, k.tgid)
                for addr in reversed(list(waker_user_stack))] + \
            [k.waker]
        print("%s %d" % (";".join(line), v.value))

    else:
        # print wakeup name then stack in reverse order
        print("    %-16s %s %s" % ("waker:", k.waker.decode(), k.t_pid))
        for addr in waker_user_stack:
            print("    %s" % b.sym(addr, k.tgid))
        if args.delimited:
            print("    -")
        for addr in waker_kernel_stack:
            print("    %s" % b.ksym(addr))

        # print waker/wakee delimiter
        print("    %-16s %s" % ("--", "--"))

        # print default multi-line stack output
        for addr in target_kernel_stack:
            print("    %s" % b.ksym(addr))
        if args.delimited:
            print("    -")
        for addr in target_user_stack:
            print("    %s" % b.sym(addr, k.tgid))
        print("    %-16s %s %s" % ("target:", k.target.decode(), k.w_pid))
        print("        %d\n" % v.value)

if missing_stacks > 0:
    enomem_str = " Consider increasing --stack-storage-size."
    print("WARNING: %d stack traces could not be displayed.%s" %
        (missing_stacks, enomem_str),
        file=stderr)
