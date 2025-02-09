#!/usr/bin/env bcc-py
#
# locktrace - Trace and display lock contention stats
#
# USAGE: locktrace.py [-h] [-p PID] [-d] [--hist HIST]
#                    [--stack-storage-size STACK_STORAGE_SIZE]
#                    [duration]
#
# Copyright 2018 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 23-Mar-2018	Gisle Dankel	Created this.

from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals
from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from cStringIO import StringIO
from ctypes import c_int
from sys import stderr
from time import sleep
import argparse
import errno
import os
import re
import signal
import sys
import time


examples = """
EXAMPLES:

./locktrace
        Trace calls to sys_futex until Ctrl-C
./locktrace -p <pid>
        Trace only for the specified pid until Ctrl-C
./locktrace -p <pid> 10
        Trace the specified pid for 10 seconds
./locktrace -p <pid> --hist hists.txt
        Trace the specified pid until Ctrl-C and write per-lock
        histograms of blocked time distribution to hists.txt
"""


description = """
Trace kernel futex events and collect per-lock stats.
"""


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


parser = argparse.ArgumentParser(
    description=description,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=positive_int,
                    help="the PID to trace; if not specified, trace all")
parser.add_argument("-d", "--debug", action="store_true",
                    help="Display extra stats used for sanity checking / debugging")
parser.add_argument("--hist", type=str,
                    help="Write per-lock histograms to the specified file")
parser.add_argument("--stack-storage-size", default=1024,
                    type=positive_nonzero_int,
                    help="the number of unique stack traces that can be stored "
                         "and displayed (default 1024)")
parser.add_argument("duration", nargs="?", default=99999999,
                    type=positive_nonzero_int,
                    help="duration of trace, in seconds")
args = parser.parse_args()

pid = args.pid
duration = args.duration
sample_frequency = 99

futex_commands = [
    "FUTEX_WAIT",
    "FUTEX_WAKE",
    "FUTEX_FD",
    "FUTEX_REQUEUE",
    "FUTEX_CMP_REQUEUE",
    "FUTEX_WAKE_OP",
    "FUTEX_LOCK_PI",
    "FUTEX_UNLOCK_PI",
    "FUTEX_TRYLOCK_PI",
    "FUTEX_WAIT_BITSET",
    "FUTEX_WAKE_BITSET",
    "FUTEX_WAIT_REQUEUE_PI",
    "FUTEX_CMP_REQUEUE_PI"
]

script_path = os.path.dirname(os.path.realpath(__file__))
with open(script_path + '/locktrace.h', 'r') as bpf_file:
    bpf_src = bpf_file.read()
bpf_src += "\n\n"
with open(script_path + '/locktrace.c', 'r') as bpf_file:
    bpf_src += bpf_file.read()

debug_stats_names = []
with open(script_path + '/locktrace_dbg.inc', 'r') as dbg_file:
    debug_stats_names = map(lambda x: re.match("EMIT\((\S+)\)", x).group(1),
                            dbg_file.readlines())

debug_stats_names.insert(0, "INVALID")
bpf_src = bpf_src.replace("DEBUG_STATS_ENUM_VALS",
                          ",\n".join(debug_stats_names))
if args.debug:
    bpf_src = bpf_src.replace("HAS_DEBUG_STATS", "1")
else:
    bpf_src = bpf_src.replace("HAS_DEBUG_STATS", "0")

pid_filter = '1'
if pid:
    print("Tracing pid %d, Ctrl+C to quit." % pid, file=stderr)
    pid_filter = "pid == %d" % pid
else:
    print("Tracing all processes, Ctrl+C to quit.", file=stderr)

bpf_src = bpf_src.replace("PID_FILTER_EXPR", pid_filter)
bpf_src = bpf_src.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))

# initialize BPF
bpf_program = BPF(text=bpf_src)
bpf_program.attach_tracepoint(tp='syscalls:sys_enter_futex',
                              fn_name='on_enter_futex')
bpf_program.attach_tracepoint(tp='syscalls:sys_exit_futex',
                              fn_name='on_exit_futex')
bpf_program.attach_tracepoint(tp='sched:sched_switch',
                              fn_name='on_sched_switch')

bpf_program.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="on_perf_cycles",
    sample_period=0, sample_freq=sample_frequency)

profile_start = time.time()
matched = bpf_program.num_open_tracepoints()
if matched != 3:
    print("error: Failed to attach to one or more tracepoints (%d). Exiting." %
          (matched), file=stderr)
    exit(1)

# signal handler
def signal_ignore(signal, frame):
    print("\nInterrupted\n", file=stderr)

try:
    sleep(duration)
except KeyboardInterrupt:
    # as cleanup can take many seconds, trap Ctrl-C:
    signal.signal(signal.SIGINT, signal_ignore)
profile_end = time.time()

bpf_program.detach_tracepoint(tp='syscalls:sys_enter_futex')
bpf_program.detach_tracepoint(tp='syscalls:sys_exit_futex')
bpf_program.detach_tracepoint(tp='sched:sched_switch')
bpf_program.detach_perf_event(ev_type=PerfType.SOFTWARE,
                              ev_config=PerfSWConfig.CPU_CLOCK)
missing_stacks = 0
has_enomem = False
stats = bpf_program.get_table("lock_stats")
cycles = bpf_program.get_table("cycle_counts")
usr_stack_traces = bpf_program.get_table("usr_stack_traces")
kernel_stack_traces = bpf_program.get_table("kernel_stack_traces")
print("{'duration': %f}" % (profile_end - profile_start))
print("pid|tid|addr|blocked_us|sys_futex_us|max_blocked_us|max_sys_futex_us|" +
      "wait_count|blocked_count|wake_count|errors|usr_ms|sys_ms|" +
      "comm|kernel_stack|usr_stack|kernel_syms|usr_syms")
print("Processing trace data...", file=stderr)
for k, v in sorted(stats.items(),
                   key=lambda lock: (lock[0].tgid, lock[1].elapsed_blocked_us),
                   reverse=True):
    # handle get_stackid erorrs
    if k.usr_stack_id < 0 and k.usr_stack_id != -errno.EFAULT:
        missing_stacks += 1
        # check for an ENOMEM error
        if k.usr_stack_id == -errno.ENOMEM:
            has_enomem = True
        continue

    usr_stack = [] if k.usr_stack_id < 0 else \
        list(usr_stack_traces.walk(k.usr_stack_id))
    usr_syms = [bpf_program.sym(addr, k.tgid) for addr in usr_stack]
    print("%d|%d|0x%x|%d|%d|%d|%d|%d|%d|%d|%d|0|0|%s||%s||%s" % (
          k.tgid, k.pid, k.uaddr,
          v.elapsed_blocked_us, v.elapsed_sys_us,
          v.max_blocked_us, v.max_sys_us,
          v.wait_count, v.blocked_count, v.wake_count, v.errors, k.comm,
          ";".join(map(str, usr_stack)), ";".join(usr_syms)))

print("Processing sample data...", file=stderr)
for k, count in sorted(cycles.items(),
                   key=lambda sample: (sample[0].tgid, sample[1]),
                   reverse=True):
    # handle get_stackid erorrs
    if (k.usr_stack_id < 0 and k.usr_stack_id != -errno.EFAULT) or\
       (k.kernel_stack_id < 0 and k.kernel_stack_id != -errno.EFAULT):
        missing_stacks += 1
        # check for an ENOMEM error
        if k.usr_stack_id == -errno.ENOMEM or\
           k.kernel_stack_id == -errno.ENOMEM:
            has_enomem = True
        continue

    usr_stack = [] if k.usr_stack_id < 0 else \
        list(usr_stack_traces.walk(k.usr_stack_id))
    usr_syms = [bpf_program.sym(addr, k.tgid) for addr in usr_stack]
    usr_ms = sys_ms = 0
    if k.kernel_stack_id >= 0:
        kernel_stack = list(kernel_stack_traces.walk(k.kernel_stack_id))
        kernel_syms = [bpf_program.ksym(addr) for addr in kernel_stack]
        sys_ms = (1000 / sample_frequency) * count.value
    else:
        kernel_stack = kernel_syms = []
        usr_ms = (1000 / sample_frequency) * count.value
    print("%d|%d|0x0|0|0|0|0|0|0|0|0|%d|%d|%s|%s|%s|%s|%s" % (
          k.tgid, k.pid, usr_ms, sys_ms, k.comm,
          ";".join(map(str, kernel_stack)), ";".join(map(str, usr_stack)),
          ";".join(kernel_syms), ";".join(usr_syms)))

print("Total records: %d from tracing and %d from sampling"
      % (len(stats), len(cycles)), file=stderr)

if missing_stacks > 0:
    enomem_str = "" if not has_enomem else \
        " Consider increasing --stack-storage-size."
    print("WARNING: %d records/samples were lost. %s" %
        (missing_stacks, enomem_str),
        file=stderr)

if args.hist:
    def print_section(key):
        return "%x [%d]" % (key[0], key[1])

    with open(args.hist, 'w') as hist_file:
        dist = bpf_program["dist"]
        stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            dist.print_log2_hist("usecs",
                                 "Lock addr",
                                 section_print_fn=print_section,
                                 bucket_fn=lambda k: (k.uaddr, k.tgid),
                                 strip_leading_zero=True)
        except TypeError:
            dist.print_log2_hist("usecs",
                                 "Lock addr",
                                 section_print_fn=print_section,
                                 bucket_fn=lambda k: (k.uaddr, k.tgid))
        hists = sys.stdout.getvalue()
        sys.stdout = stdout
        for hist in hists.split("Lock addr")[1:]:
            m = re.match(" = ([0-9a-f]+) \[(\d+)\]", hist)
            if m is None:
                print(hist)
                print("ERROR: Invalid histogram")
            else:
                uaddr = int(m.group(1), 16)
                pid = int(m.group(2))
                hist_file.write("PID %d, LOCK 0x%x" % (pid, uaddr))
                hist_file.write(hist[hist.find("\n") + 1:])

if args.debug:
    stats = bpf_program['dbg_stats']
    print("\nDebug stats:", file=stderr)
    for key in sorted(stats.keys(), key=lambda x: x.value):
        if key.value & ~0xff:
            key_name = "%s_%s" % (debug_stats_names[key.value >> 16],
                                  futex_commands[key.value & 0xff])
        else:
            key_name = debug_stats_names[key.value]
        print("%-55s %10i" % (key_name, stats[key].value), file=stderr)
