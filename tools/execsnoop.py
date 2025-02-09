#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# execsnoop Trace new processes via exec() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: execsnoop [-h] [-T] [-t] [-x] [--cgroupmap CGROUPMAP]
#                  [--mntnsmap MNTNSMAP] [-u USER] [-q] [-n NAME] [-l LINE]
#                  [-U] [--max-args MAX_ARGS] [-P PPID]
#
# This currently will print up to a maximum of 19 arguments, plus the process
# name, so 20 fields in total (MAXARG).
#
# This won't catch all new processes: an application may fork() but not exec().
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.
# 11-Aug-2022   Rocky Xing      Added PPID filter support.

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import argparse
import re
import time
import pwd
from collections import defaultdict
from time import strftime


def parse_uid(user):
    try:
        result = int(user)
    except ValueError:
        try:
            user_info = pwd.getpwnam(user)
        except KeyError:
            raise argparse.ArgumentTypeError(
                "{0!r} is not valid UID or user entry".format(user))
        else:
            return user_info.pw_uid
    else:
        # Maybe validate if UID < 0 ?
        return result


# arguments
examples = """examples:
    ./execsnoop                      # trace all exec() syscalls
    ./execsnoop -x                   # include failed exec()s
    ./execsnoop -T                   # include time (HH:MM:SS)
    ./execsnoop -P 181               # only trace new processes whose parent PID is 181
    ./execsnoop -U                   # include UID
    ./execsnoop -C                   # include CPU
    ./execsnoop -M                   # include PCOMM
    ./execsnoop -u 1000              # only trace UID 1000
    ./execsnoop -u user              # get user UID and trace only them
    ./execsnoop -t                   # include timestamps
    ./execsnoop -q                   # add "quotemarks" around arguments
    ./execsnoop -n main              # only print command lines containing "main"
    ./execsnoop -l tpkg              # only print command where arguments contains "tpkg"
    ./execsnoop --cgroupmap mappath  # only trace cgroups in this BPF map
    ./execsnoop --mntnsmap mappath   # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Trace exec() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--time", action="store_true",
    help="include time column on output (HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-x", "--fails", action="store_true",
    help="include failed exec()s")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("-u", "--uid", type=parse_uid, metavar='USER',
    help="trace this UID only")
parser.add_argument("-q", "--quote", action="store_true",
    help="Add quotemarks (\") around arguments."
    )
parser.add_argument("-n", "--name",
    type=ArgString,
    help="only print commands matching this name (regex), any arg")
parser.add_argument("-l", "--line",
    type=ArgString,
    help="only print commands where arg contains this line (regex)")
parser.add_argument("-U", "--print-uid", action="store_true",
    help="print UID column")
parser.add_argument("-C", "--print-cpu", action="store_true",
    help="print CPU column")
parser.add_argument("-M", "--print-pcomm", action="store_true",
    help="print parent command")
parser.add_argument("--max-args", default="20",
    help="maximum number of arguments parsed and displayed, defaults to 20")
parser.add_argument("-P", "--ppid",
    help="trace this parent PID only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

def check_cpu_filed():
    # Define the bpf program for checking purpose
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,16,0)
    filed_in_task_struct = True
#else
    filed_in_task_struct = False
#endif

    return filed_in_task_struct


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 uid;
    u32 cpu;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

struct val_t {
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

BPF_HASH(entryinfo, u64, struct val_t);
BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int parse_argv_envp(struct pt_regs *ctx)
{
    struct val_t *valp;
    u64 id = bpf_get_current_pid_tgid();

    valp = entryinfo.lookup(&id);
    if (valp == 0) {
        // missed tracing issue or filtered
        return 0;
    }

    const char *filename = valp->filename;
    const char *const *__argv = valp->argv;
    const char *const *__envp = valp->envp;

    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;
    bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), task->real_parent->comm);

    PPID_FILTER

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    UID_FILTER

    if (container_should_be_filtered()) {
        return 0;
    }

    u64 id =  bpf_get_current_pid_tgid();
    struct val_t val = {
        .filename = filename,
        .argv = __argv,
        .envp = __envp,
    };

    entryinfo.update(&id, &val);
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    if (container_should_be_filtered()) {
        return 0;
    }

    struct data_t data = {};
    struct task_struct *task;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    UID_FILTER

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = uid;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;
    bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), task->real_parent->comm);
    data.cpu = CPU_RUNNING_ON;

    PPID_FILTER

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

bpf_text = bpf_text.replace("MAXARG", args.max_args)

if args.uid:
    bpf_text = bpf_text.replace('UID_FILTER',
        'if (uid != %s) { return 0; }' % args.uid)
else:
    bpf_text = bpf_text.replace('UID_FILTER', '')

if args.ppid:
    bpf_text = bpf_text.replace('PPID_FILTER',
        'if (data.ppid != %s) { return 0; }' % args.ppid)
else:
    bpf_text = bpf_text.replace('PPID_FILTER', '')

# CPU field moved back into thread_info since commit bcf9033e5449(linux 5.16)
# Use BTF for CPU field checks if available, otherwise use LINUX_VERSION_CODE checking.
if BPF.kernel_struct_has_field(b'task_struct', b'cpu') == 1 \
        or check_cpu_filed():
    bpf_text = bpf_text.replace('CPU_RUNNING_ON', 'task->cpu')
else:
    bpf_text = bpf_text.replace('CPU_RUNNING_ON', 'task->thread_info.cpu')

bpf_text = filter_by_containers(args) + bpf_text
if args.ebpf:
    print(bpf_text)
    exit()

# initialize BPF
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
if BPF.get_kprobe_functions(b'prepare_binprm'):
    b.attach_kprobe(event="prepare_binprm", fn_name="parse_argv_envp")
else:
    b.attach_kprobe(event="bprm_execve", fn_name="parse_argv_envp")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

# header
if args.time:
    print("%-9s" % ("TIME"), end="")
if args.timestamp:
    print("%-8s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
print("%-16s %-7s " % ("COMM", "PID"), end="")
if args.print_pcomm:
    print("%-16s " % ("PCOMM"), end="")
print("%-7s " % ("PPID"), end="")
if args.print_cpu:
    print("%-4s " % ("CPU"), end="")
print("%3s %s" % ("RET", "ARGS"))

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

start_ts = time.time()
argv = defaultdict(list)

# This is best-effort PPID matching. Short-lived processes may exit
# before we get a chance to read the PPID.
# This is a fallback for when fetching the PPID from task->real_parent->tgip
# returns 0, which happens in some kernel versions.
def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    skip = False

    if event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        if event.retval != 0 and not args.fails:
            skip = True
        if args.name and not re.search(bytes(args.name), event.comm):
            skip = True
        if args.line and not re.search(bytes(args.line),
                                       b' '.join(argv[event.pid])):
            skip = True
        if args.quote:
            argv[event.pid] = [
                b"\"" + arg.replace(b"\"", b"\\\"") + b"\""
                for arg in argv[event.pid]
            ]

        if not skip:
            if args.time:
                printb(b"%-9s" % strftime("%H:%M:%S").encode('ascii'), nl="")
            if args.timestamp:
                printb(b"%-8.3f" % (time.time() - start_ts), nl="")
            if args.print_uid:
                printb(b"%-6d" % event.uid, nl="")
            ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
            ppid = b"%d" % ppid if ppid > 0 else b"?"
            argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
            printb(b"%-16s %-7d " % (event.comm, event.pid), nl="")
            if args.print_pcomm:
                printb(b"%-16s " % (event.pcomm), nl="")
            printb(b"%-7s " % (ppid), nl="")
            if args.print_cpu:
                printb(b"%-4d " % (event.cpu), nl="")
            printb(b"%3d %s" % (event.retval, argv_text))
        try:
            del(argv[event.pid])
        except Exception:
            pass


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
