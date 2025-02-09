#!/usr/bin/env python
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
# 04-Apr-2023   Rocky Xing      Updated default stack storage size.

from __future__ import print_function
from bcc import BPF
from time import sleep
import argparse
import signal
import errno
from sys import stderr

# arg validation
def positive_int(val):
    dest = []
    # Filter up to 5 pids, arbitrary
    args_list = val.split(",", 5)
    pids_to_add = min(len(args_list), 5)
    for i in range(pids_to_add):
        dest.append(_positive_int(args_list[i]))

    return dest

def _positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

def positive_nonzero_int(val):
    ival = _positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

def build_filter(filter_name, values):
    filter_string = "((%s == %d)" % (filter_name, values[0])

    for val in values[1:]:
        filter_string += " || (%s == %d )" % (filter_name , val)

    filter_string += ")"

    return filter_string

def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not available,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

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
thread_group.add_argument("-p", "--pid", metavar="PIDS", dest="tgid",
     type=positive_int,
     help="trace these PIDS only. Can be a comma separated list of PIDS.")
thread_group.add_argument("-t", "--tid", metavar="TIDS", dest="pid",
    type=positive_int,
    help="trace these TIDS only. Can be a comma separated list of TIDS.")
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
parser.add_argument("--stack-storage-size", default=16384,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and "
         "displayed (default 16384)")
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
parser.add_argument("--state", type=_positive_int,
    help="filter on this thread state bitmask (eg, 2 == TASK_UNINTERRUPTIBLE" +
         ") see include/linux/sched.h")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
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
    s64 w_k_stack_id;
    s64 w_u_stack_id;
    s64 t_k_stack_id;
    s64 t_u_stack_id;
    u64 t_pid;
    u64 t_tgid;
    u32 w_pid;
    u32 w_tgid;
};
BPF_HASH(counts, struct key_t);

// Key of this hash is PID of waiting Process,
// value is timestamp when it went into waiting
BPF_HASH(start, u32);

struct wokeby_t {
    char name[TASK_COMM_LEN];
    int k_stack_id;
    int u_stack_id;
    int w_pid;
    int w_tgid;
};
// Key of the hash is PID of the Process to be waken, value is information
// of the Process who wakes it
BPF_HASH(wokeby, u32, struct wokeby_t);

BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

int waker(struct pt_regs *ctx, struct task_struct *p) {
    // PID and TGID of the target Process to be waken
    u32 pid = p->pid;
    u32 tgid = p->tgid;

    if (pid == 0 || !((THREAD_FILTER) && (STATE_FILTER))) {
        return 0;
    }

    // Construct information about current (the waker) Process
    struct wokeby_t woke = {};
    bpf_get_current_comm(&woke.name, sizeof(woke.name));
    woke.k_stack_id = KERNEL_STACK_GET;
    woke.u_stack_id = USER_STACK_GET;
    woke.w_pid = bpf_get_current_pid_tgid();
    woke.w_tgid = bpf_get_current_pid_tgid() >> 32;

    wokeby.update(&pid, &woke);
    return 0;
}

int oncpu(struct pt_regs *ctx, struct task_struct *p) {
    // PID and TGID of the previous Process (Process going into waiting)
    u32 pid = p->pid;
    u32 tgid = p->tgid;
    u64 *tsp;
    u64 ts = bpf_ktime_get_ns();

    // Record timestamp for the previous Process (Process going into waiting)
    if (pid != 0 && (THREAD_FILTER) && (STATE_FILTER)) {
        start.update(&pid, &ts);
    }

    // Calculate current Process's wait time by finding the timestamp of when
    // it went into waiting.
    // pid and tgid are now the PID and TGID of the current (waking) Process.
    pid = bpf_get_current_pid_tgid();
    if (pid == 0) {
        return 0;
    }
    tgid = bpf_get_current_pid_tgid() >> 32;
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        // Missed or filtered when the Process went into waiting
        return 0;
    }
    u64 delta = ts - *tsp;
    start.delete(&pid);
    delta = delta / 1000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
        return 0;
    }

    // create map key
    struct key_t key = {};
    struct wokeby_t *woke;

    bpf_get_current_comm(&key.target, sizeof(key.target));
    key.t_pid = pid;
    key.t_tgid = tgid;
    key.t_k_stack_id = KERNEL_STACK_GET;
    key.t_u_stack_id = USER_STACK_GET;

    woke = wokeby.lookup(&pid);
    if (woke) {
        key.w_k_stack_id = woke->k_stack_id;
        key.w_u_stack_id = woke->u_stack_id;
        key.w_pid = woke->w_pid;
        key.w_tgid = woke->w_tgid;
        __builtin_memcpy(&key.waker, woke->name, TASK_COMM_LEN);
        wokeby.delete(&pid);
    }

    counts.increment(key, delta);
    return 0;
}
"""

# set thread filter
if args.tgid is not None:
    thread_filter = build_filter("tgid", args.tgid)
elif args.pid is not None:
    thread_filter = build_filter("pid", args.pid)
elif args.user_threads_only:
    thread_filter = '!(p->flags & PF_KTHREAD)'
elif args.kernel_threads_only:
    thread_filter = 'p->flags & PF_KTHREAD'
else:
    thread_filter = '1'
if args.state == 0:
    state_filter = 'p->STATE_FIELD == 0'
elif args.state:
    # these states are sometimes bitmask checked
    state_filter = 'p->STATE_FIELD & %d' % args.state
else:
    state_filter = '1'
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)
bpf_text = bpf_text.replace('STATE_FILTER', state_filter)
if BPF.kernel_struct_has_field(b'task_struct', b'__state') == 1:
    bpf_text = bpf_text.replace('STATE_FIELD', '__state')
else:
    bpf_text = bpf_text.replace('STATE_FIELD', 'state')

# set stack storage size
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))
bpf_text = bpf_text.replace('MINBLOCK_US_VALUE', str(args.min_block_time))
bpf_text = bpf_text.replace('MAXBLOCK_US_VALUE', str(args.max_block_time))

# handle stack args
kernel_stack_get = "stack_traces.get_stackid(ctx, 0)"
user_stack_get = "stack_traces.get_stackid(ctx, BPF_F_USER_STACK)"
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
if args.ebpf:
    print(bpf_text)
    exit()

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event_re=r'^finish_task_switch$|^finish_task_switch\.isra\.\d$',
                fn_name="oncpu")
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

try:
    sleep(duration)
except KeyboardInterrupt:
    # as cleanup can take many seconds, trap Ctrl-C:
    # print a newline for folded output on Ctrl-C
    signal.signal(signal.SIGINT, signal_ignore)


if not folded:
    print()

missing_stacks = 0
has_enomem = False
counts = b.get_table("counts")
stack_traces = b.get_table("stack_traces")
need_delimiter = args.delimited and not (args.kernel_stacks_only or
                                         args.user_stacks_only)
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    # handle get_stackid errors
    if not args.user_stacks_only:
        missing_stacks += int(stack_id_err(k.w_k_stack_id))
        missing_stacks += int(stack_id_err(k.t_k_stack_id))
        has_enomem = has_enomem or (k.w_k_stack_id == -errno.ENOMEM) or \
                     (k.t_k_stack_id == -errno.ENOMEM)
    if not args.kernel_stacks_only:
        missing_stacks += int(stack_id_err(k.w_u_stack_id))
        missing_stacks += int(stack_id_err(k.t_u_stack_id))
        has_enomem = has_enomem or (k.w_u_stack_id == -errno.ENOMEM) or \
                     (k.t_u_stack_id == -errno.ENOMEM)

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
        line = [k.target.decode('utf-8', 'replace')]
        if not args.kernel_stacks_only:
            if stack_id_err(k.t_u_stack_id):
                line.append("[Missed User Stack] %d" % k.t_u_stack_id)
            else:
                line.extend([b.sym(addr, k.t_tgid).decode('utf-8', 'replace')
                    for addr in reversed(list(target_user_stack)[1:])])
        if not args.user_stacks_only:
            line.extend(["-"] if (need_delimiter and k.t_k_stack_id > 0 and k.t_u_stack_id > 0) else [])
            if stack_id_err(k.t_k_stack_id):
                line.append("[Missed Kernel Stack]")
            else:
                line.extend([b.ksym(addr).decode('utf-8', 'replace')
                    for addr in reversed(list(target_kernel_stack)[1:])])
        line.append("--")
        if not args.user_stacks_only:
            if stack_id_err(k.w_k_stack_id):
                line.append("[Missed Kernel Stack]")
            else:
                line.extend([b.ksym(addr).decode('utf-8', 'replace')
                    for addr in reversed(list(waker_kernel_stack))])
        if not args.kernel_stacks_only:
            line.extend(["-"] if (need_delimiter and k.w_u_stack_id > 0 and k.w_k_stack_id > 0) else [])
            if stack_id_err(k.w_u_stack_id):
                line.append("[Missed User Stack]")
            else:
                line.extend([b.sym(addr, k.w_tgid).decode('utf-8', 'replace')
                    for addr in reversed(list(waker_user_stack))])
        line.append(k.waker.decode('utf-8', 'replace'))
        print("%s %d" % (";".join(line), v.value))
    else:
        # print wakeup name then stack in reverse order
        print("    %-16s %s %s" % ("waker:", k.waker.decode('utf-8', 'replace'), k.w_pid))
        if not args.kernel_stacks_only:
            if stack_id_err(k.w_u_stack_id):
                print("    [Missed User Stack] %d" % k.w_u_stack_id)
            else:
                for addr in waker_user_stack:
                    print("    %s" % b.sym(addr, k.w_tgid).decode('utf-8', 'replace'))
        if not args.user_stacks_only:
            if need_delimiter and k.w_u_stack_id > 0 and k.w_k_stack_id > 0:
                print("    -")
            if stack_id_err(k.w_k_stack_id):
                print("    [Missed Kernel Stack]")
            else:
                for addr in waker_kernel_stack:
                    print("    %s" % b.ksym(addr).decode('utf-8', 'replace'))

        # print waker/wakee delimiter
        print("    %-16s %s" % ("--", "--"))

        if not args.user_stacks_only:
            if stack_id_err(k.t_k_stack_id):
                print("    [Missed Kernel Stack]")
            else:
                for addr in target_kernel_stack:
                    print("    %s" % b.ksym(addr).decode('utf-8', 'replace'))
        if not args.kernel_stacks_only:
            if need_delimiter and k.t_u_stack_id > 0 and k.t_k_stack_id > 0:
                print("    -")
            if stack_id_err(k.t_u_stack_id):
                print("    [Missed User Stack]")
            else:
                for addr in target_user_stack:
                    print("    %s" % b.sym(addr, k.t_tgid).decode('utf-8', 'replace'))
        print("    %-16s %s %s" % ("target:", k.target.decode('utf-8', 'replace'), k.t_pid))
        print("        %d\n" % v.value)

if missing_stacks > 0:
    enomem_str = " Consider increasing --stack-storage-size."
    print("WARNING: %d stack traces lost and could not be displayed.%s" %
        (missing_stacks, (enomem_str if has_enomem else "")),
        file=stderr)
