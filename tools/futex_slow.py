#!/usr/bin/env python3
#
# Copyright 2024 IONOS SE
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Author: Max Kellermann <max.kellermann@ionos.com>

import argparse
import ctypes
from datetime import datetime
import sys
from bcc import BPF

# arguments
examples = """examples:
    futex_slow               # trace futexes slower than 10 ms (default)
    futex_slow 1             # trace futexes slower than 1 ms
    futex_slow -p 185        # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Show long futex wait times",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("min_ms", nargs="?", default='10',
    help="minimum wait duration to trace, in ms (default 10)")
parser.add_argument("-g", "--call-graph",
    help="enables call-graph", action="store_true")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

if len(sys.argv) < 2:
    print("USAGE: futex_slow.py PID", file=sys.stderr)
    sys.exit(1)

text = f"""
#define MIN_NS {int(args.min_ms) * 1_000_000}
"""

if args.pid is not None:
    text += f"#define PID {args.pid}\n"

if args.call_graph:
    text += '#define CALL_GRAPH'

text += """
#include <uapi/linux/futex.h>
#include <uapi/linux/ptrace.h>

struct task_waiter {
    u64 futex_address;
};

struct futex_waiter {
    u64 start_ns;
    u32 n_waiters;
    u32 n_woken, n_eagain, n_errors;
};

struct data_t {
    u64 futex_address;
    struct futex_waiter waiter;
    u64 wait_ns;
    u64 pid_tgid;
    int stack_id;
};

BPF_PERF_OUTPUT(events);

BPF_HASH(waiting_tasks, u32, struct task_waiter);
BPF_HASH(waiting_futexes, u64, struct futex_waiter);

#ifdef CALL_GRAPH
BPF_STACK_TRACE(stack_traces, 1024);
#endif

static void add_waiting_futex(struct pt_regs *ctx, u64 futex_address) {
    struct futex_waiter *p = waiting_futexes.lookup(&futex_address);
    if (p == NULL) {
        struct futex_waiter w = {
            .start_ns = bpf_ktime_get_ns(),
            .n_waiters = 1,
        };
        waiting_futexes.update(&futex_address, &w);
    } else {
        ++p->n_waiters;
    }

    u32 pid = bpf_get_current_pid_tgid();
    struct task_waiter tw = {
        .futex_address = futex_address,
    };
    waiting_tasks.update(&pid, &tw);
}

static void remove_waiting_futex(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct task_waiter *tw = waiting_tasks.lookup(&pid);
    if (tw == NULL)
        return;

    u64 futex_address = tw->futex_address;
    waiting_tasks.delete(&pid);

    struct futex_waiter *fw = waiting_futexes.lookup(&futex_address);
    if (fw != NULL) {
        const int ret = PT_REGS_RC(ctx);
        if (ret == 0)
            ++fw->n_woken;
        else if (ret == -EAGAIN) {
            ++fw->n_eagain;

            if (fw->n_waiters == fw->n_eagain && fw->n_woken == 0 && fw->n_errors == 0) {
                // race with locker who already invoked WAKE: discard this record
                waiting_futexes.delete(&futex_address);
            }
        } else
            ++fw->n_errors;
    }
}

static void futex_woken(struct pt_regs *ctx, u64 futex_address) {
    struct futex_waiter *fwp = waiting_futexes.lookup(&futex_address);
    if (fwp == NULL)
        return;

    const struct futex_waiter fw = *fwp;
    u64 ns = bpf_ktime_get_ns() - fw.start_ns;

    waiting_futexes.delete(&futex_address);

    // only print slow (>= 10ms) lockers
    // TODO hard-coded threshold
    if (ns < MIN_NS)
        return;

    struct data_t data = {
        .futex_address = futex_address,
        .waiter = fw,
        .wait_ns = ns,
        .pid_tgid = bpf_get_current_pid_tgid(),
#ifdef CALL_GRAPH
        .stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK),
#endif
    };
    events.perf_submit(ctx, &data, sizeof(data));
}

int syscall__futex(struct pt_regs *ctx, uint32_t *uaddr, int futex_op)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
#ifdef PID
    if (tgid != PID)
        return 0;
#endif

    const int op = futex_op & FUTEX_CMD_MASK;
    if (op == FUTEX_WAIT) {
        // caller wants to lock but sees contention
        add_waiting_futex(ctx, (u64)uaddr);
    } else if (op == FUTEX_WAKE) {
        // caller has unlocked and wakes up a waiter
        futex_woken(ctx, (u64)uaddr);
    }

    return 0;
};

int syscall__futex_return(struct pt_regs *ctx)
{
    remove_waiting_futex(ctx);
    return 0;
};

"""
    
if args.ebpf:
    print(text)
    sys.exit(0)

# load BPF program
b = BPF(text=text)

b.attach_kprobe(event=b.get_syscall_fnname("futex"),
                fn_name="syscall__futex")

b.attach_kretprobe(event=b.get_syscall_fnname("futex"),
                   fn_name="syscall__futex_return")

class Data(ctypes.Structure):
    _fields_ = [
        ("futex_address", ctypes.c_ulonglong),
        ("start_ns", ctypes.c_ulonglong),
        ("n_waiters", ctypes.c_uint),
        ("n_woken", ctypes.c_uint),
        ("n_eagain", ctypes.c_uint),
        ("n_errors", ctypes.c_uint),
        ("wait_ns", ctypes.c_ulonglong),
        ("pid_tgid", ctypes.c_ulonglong),
        ("stack_id", ctypes.c_int),
    ]

if args.call_graph:
    stack_traces = b["stack_traces"]

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    print("%-12s %7d 0x%x %7dms %7d %7d %7d %7d" % (
        datetime.utcnow().isoformat(timespec='milliseconds').split('T')[1],
        event.pid_tgid & 0xffff_ffff,
        event.futex_address,
        event.wait_ns // 1000000,
        event.n_waiters,
        event.n_woken,
        event.n_eagain,
        event.n_errors,
    ))

    if args.call_graph and event.stack_id >= 0:
        w = stack_traces.walk(event.stack_id)
        for addr in list(w):
            print("  %s" % b.sym(addr, event.pid_tgid >> 32).decode('utf-8', 'replace'))

print("%-12s %7s %14s "
      "%9s "
      "%7s %7s %7s %7s" % (
    'time', 'pid', 'futex_addr',
    'wait_time',
    'waiters', 'woken', 'eagain', 'errors',
))

b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.kprobe_poll()
