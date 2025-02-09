#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# killsnoop Trace signals issued by the kill() syscall.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: killsnoop [-h] [-x] [-p PID] [-T PID] [-s SIGNAL]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg   Created this.
# 19-Feb-2016   Allan McAleavy migrated to BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
from bcc.utils import ArgString, printb
import argparse
from time import strftime

# arguments
examples = """examples:
    ./killsnoop           # trace all kill() signals
    ./killsnoop -x        # only show failed kills
    ./killsnoop -p 181    # only trace PID 181
    ./killsnoop -T 189    # only trace target PID 189
    ./killsnoop -s 9      # only trace signal 9
    ./killsnoop -s 9,15   # trace signal 9 and 15
"""
parser = argparse.ArgumentParser(
    description="Trace signals issued by the kill() syscall",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed kill syscalls")
parser.add_argument("-p", "--pid",
    help="trace this PID only which is the sender of signal")
parser.add_argument("-T", "--tpid",
    help="trace this target PID only which is the receiver of signal")
parser.add_argument("-s", "--signal",
    help="trace a signal or a signal list")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct val_t {
   u32 pid;
   int sig;
   int tpid;
   char comm[TASK_COMM_LEN];
};

struct data_t {
   u32 pid;
   int tpid;
   int sig;
   int ret;
   char comm[TASK_COMM_LEN];
};

BPF_HASH(infotmp, u32, struct val_t);
BPF_PERF_OUTPUT(events);

int syscall__kill(struct pt_regs *ctx, int tpid, int sig)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    TPID_FILTER
    PID_FILTER
    SIGNAL_FILTER

    struct val_t val = {.pid = pid};
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.tpid = tpid;
        val.sig = sig;
        infotmp.update(&tid, &val);
    }

    return 0;
};

int do_ret_sys_kill(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct val_t *valp;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    valp = infotmp.lookup(&tid);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    data.pid = pid;
    data.tpid = valp->tpid;
    data.ret = PT_REGS_RC(ctx);
    data.sig = valp->sig;

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&tid);

    return 0;
}
"""

if args.tpid:
    bpf_text = bpf_text.replace('TPID_FILTER',
        'if (tpid != %s) { return 0; }' % args.tpid)
else:
    bpf_text = bpf_text.replace('TPID_FILTER', '')

if args.pid:
    bpf_text = bpf_text.replace('PID_FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('PID_FILTER', '')

if args.signal:
    signals = args.signal.split(',')
    signal_filter = ' && '.join(['sig != %s' % signal for signal in signals])
    bpf_text = bpf_text.replace('SIGNAL_FILTER',
        'if (%s) { return 0; }' % signal_filter)
else:
    bpf_text = bpf_text.replace('SIGNAL_FILTER', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
kill_fnname = b.get_syscall_fnname("kill")
b.attach_kprobe(event=kill_fnname, fn_name="syscall__kill")
b.attach_kretprobe(event=kill_fnname, fn_name="do_ret_sys_kill")

# detect the length of PID column
pid_bytes = 6
try:
    with open("/proc/sys/kernel/pid_max", 'r') as f:
        pid_bytes = len(f.read().strip()) + 1
        f.close()
except:
    pass # not fatal error, just use the default value

# header
print("%-9s %-*s %-16s %-4s %-*s %s" % (
    "TIME", pid_bytes, "PID", "COMM", "SIG", pid_bytes, "TPID", "RESULT"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    if (args.failed and (event.ret >= 0)):
        return
    
    tpid = event.tpid
    if (tpid & (1 << (64 - 1 ))) != 0:
        tpid = tpid - (1<<64)

    printb(b"%-9s %-*d %-16s %-4d %-*d %d" % (strftime("%H:%M:%S").encode('ascii'),
        pid_bytes, event.pid, event.comm, event.sig, pid_bytes, event.tpid, event.ret))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
