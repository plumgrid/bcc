#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# opensnoop Trace open() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: opensnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID]
#                  [--cgroupmap CGROUPMAP] [--mntnsmap MNTNSMAP] [-u UID]
#                  [-d DURATION] [-n NAME] [-F] [-e] [-f FLAG_FILTER]
#                  [-b BUFFER_PAGES]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 17-Sep-2015   Brendan Gregg   Created this.
# 29-Apr-2016   Allan McAleavy  Updated for BPF_PERF_OUTPUT.
# 08-Oct-2016   Dina Goldshtein Support filtering by PID and TID.
# 28-Dec-2018   Tim Douglas     Print flags argument, enable filtering
# 06-Jan-2019   Takuma Kume     Support filtering by UID
# 21-Aug-2022   Rocky Xing      Support showing full path for an open file.
# 06-Sep-2022   Rocky Xing      Support setting size of the perf ring buffer.

from __future__ import print_function
from bcc import ArgString, BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from collections import defaultdict
from datetime import datetime, timedelta
import os

# arguments
examples = """examples:
    ./opensnoop                        # trace all open() syscalls
    ./opensnoop -T                     # include timestamps
    ./opensnoop -U                     # include UID
    ./opensnoop -x                     # only show failed opens
    ./opensnoop -p 181                 # only trace PID 181
    ./opensnoop -t 123                 # only trace TID 123
    ./opensnoop -u 1000                # only trace UID 1000
    ./opensnoop -d 10                  # trace for 10 seconds only
    ./opensnoop -n main                # only print process names containing "main"
    ./opensnoop -e                     # show extended fields
    ./opensnoop -f O_WRONLY -f O_RDWR  # only print calls for writing
    ./opensnoop -F                     # show full path for an open file with relative path
    ./opensnoop --cgroupmap mappath    # only trace cgroups in this BPF map
    ./opensnoop --mntnsmap mappath     # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Trace open() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-U", "--print-uid", action="store_true",
    help="print UID column")
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed opens")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-t", "--tid",
    help="trace this TID only")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("-u", "--uid",
    help="trace this UID only")
parser.add_argument("-d", "--duration",
    help="total duration of trace in seconds")
parser.add_argument("-n", "--name",
    type=ArgString,
    help="only print process names containing this name")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-e", "--extended_fields", action="store_true",
    help="show extended fields")
parser.add_argument("-f", "--flag_filter", action="append",
    help="filter on flags argument (e.g., O_WRONLY)")
parser.add_argument("-F", "--full-path", action="store_true",
    help="show full path for an open file with relative path")
parser.add_argument("-b", "--buffer-pages", type=int, default=64,
    help="size of the perf ring buffer "
        "(must be a power of two number of pages and defaults to 64)")
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))
flag_filter_mask = 0
for flag in args.flag_filter or []:
    if not flag.startswith('O_'):
        exit("Bad flag: %s" % flag)
    try:
        flag_filter_mask |= getattr(os, flag)
    except AttributeError:
        exit("Bad flag: %s" % flag)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#ifdef FULLPATH
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mount.h>

#define MAX_ENTRIES 32

enum event_type {
    EVENT_ENTRY,
    EVENT_END,
    EVENT_MOUNTPOINT,
};
#endif

struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char *fname;
    int flags; // EXTENDED_STRUCT_MEMBER
    u32 mode; // EXTENDED_STRUCT_MEMBER
};

struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
#ifdef FULLPATH
    u32 mnt_dev; // actually of type 'dev_t', which is currently a redefinition of u32 in `linux/types.h`
    enum event_type type;
#endif
    char name[NAME_MAX];
    int flags; // EXTENDED_STRUCT_MEMBER
    u32 mode; // EXTENDED_STRUCT_MEMBER
};

BPF_PERF_OUTPUT(events);
"""

bpf_text_kprobe = """
BPF_HASH(infotmp, u64, struct val_t);

int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};

    u64 tsp = bpf_ktime_get_ns();

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read_user_str(&data.name, sizeof(data.name), (void *)valp->fname);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.uid = bpf_get_current_uid_gid();
    data.flags = valp->flags; // EXTENDED_STRUCT_MEMBER
    data.mode = valp->mode; // EXTENDED_STRUCT_MEMBER
    data.ret = PT_REGS_RC(ctx);

    SUBMIT_DATA

    infotmp.delete(&id);

    return 0;
}
"""

bpf_text_kprobe_header_open = """
int syscall__trace_entry_open(struct pt_regs *ctx, const char __user *filename,
                              int flags, u32 mode)
{
"""

bpf_text_kprobe_header_openat = """
int syscall__trace_entry_openat(struct pt_regs *ctx, int dfd,
                                const char __user *filename, int flags,
                                u32 mode)
{
"""

bpf_text_kprobe_header_openat2 = """
#include <uapi/linux/openat2.h>
int syscall__trace_entry_openat2(struct pt_regs *ctx, int dfd, const char __user *filename, struct open_how *how)
{
    int flags = how->flags;
    u32 mode = 0;

    if (flags & O_CREAT || (flags & O_TMPFILE) == O_TMPFILE)
        mode = how->mode;
"""

bpf_text_kprobe_body = """
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();

    PID_TID_FILTER
    UID_FILTER
    FLAGS_FILTER

    if (container_should_be_filtered()) {
        return 0;
    }

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // EXTENDED_STRUCT_MEMBER
        val.mode = mode; // EXTENDED_STRUCT_MEMBER
        infotmp.update(&id, &val);
    }

    return 0;
};
"""

bpf_text_kfunc_header_open = """
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    const char __user *filename = (char *)PT_REGS_PARM1(regs);
    int flags = PT_REGS_PARM2(regs);
    u32 mode = 0;

    /**
     * open(2): The mode argument must be supplied if O_CREAT or O_TMPFILE is
     * specified in flags; if it is not supplied, some arbitrary bytes from
     * the stack will be applied as the file mode.
     *
     * Other O_CREAT | O_TMPFILE checks about flags are also for this reason.
     */
    if (flags & O_CREAT || (flags & O_TMPFILE) == O_TMPFILE)
        mode = PT_REGS_PARM3(regs);
#else
KRETFUNC_PROBE(FNNAME, const char __user *filename, int flags,
               u32 mode, int ret)
{
#endif
"""

bpf_text_kfunc_header_openat = """
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    int flags = PT_REGS_PARM3(regs);
    u32 mode = 0;

    if (flags & O_CREAT || (flags & O_TMPFILE) == O_TMPFILE)
        mode = PT_REGS_PARM4(regs);
#else
KRETFUNC_PROBE(FNNAME, int dfd, const char __user *filename, int flags,
               u32 mode, int ret)
{
#endif
"""

bpf_text_kfunc_header_openat2 = """
#include <uapi/linux/openat2.h>
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    struct open_how __user how;
    int flags;
    u32 mode = 0;

    bpf_probe_read_user(&how, sizeof(struct open_how), (struct open_how*)PT_REGS_PARM3(regs));
    flags = how.flags;

    if (flags & O_CREAT || (flags & O_TMPFILE) == O_TMPFILE)
        mode = how.mode;
#else
KRETFUNC_PROBE(FNNAME, int dfd, const char __user *filename, struct open_how __user *how, int ret)
{
    int flags = how->flags;
    u32 mode = 0;

    if (flags & O_CREAT || (flags & O_TMPFILE) == O_TMPFILE)
        mode = how->mode;
#endif
"""

bpf_text_kfunc_body = """
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();

    PID_TID_FILTER
    UID_FILTER
    FLAGS_FILTER
    if (container_should_be_filtered()) {
        return 0;
    }

    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    u64 tsp = bpf_ktime_get_ns();

    bpf_probe_read_user_str(&data.name, sizeof(data.name), (void *)filename);
    data.id    = id;
    data.ts    = tsp / 1000;
    data.uid   = bpf_get_current_uid_gid();
    data.flags = flags; // EXTENDED_STRUCT_MEMBER
    data.mode  = mode; // EXTENDED_STRUCT_MEMBER
    data.ret   = ret;

    SUBMIT_DATA

    return 0;
}
"""

b = BPF(text='')
# open and openat are always in place since 2.6.16
fnname_open = b.get_syscall_prefix().decode() + 'open'
fnname_openat = b.get_syscall_prefix().decode() + 'openat'
fnname_openat2 = b.get_syscall_prefix().decode() + 'openat2'
if b.ksymname(fnname_openat2) == -1:
    fnname_openat2 = None

if args.full_path:
    bpf_text = "#define FULLPATH\n" + bpf_text

is_support_kfunc = BPF.support_kfunc()
if is_support_kfunc:
    bpf_text += bpf_text_kfunc_header_open.replace('FNNAME', fnname_open)
    bpf_text += bpf_text_kfunc_body

    bpf_text += bpf_text_kfunc_header_openat.replace('FNNAME', fnname_openat)
    bpf_text += bpf_text_kfunc_body

    if fnname_openat2:
        bpf_text += bpf_text_kfunc_header_openat2.replace('FNNAME', fnname_openat2)
        bpf_text += bpf_text_kfunc_body
else:
    bpf_text += bpf_text_kprobe

    bpf_text += bpf_text_kprobe_header_open
    bpf_text += bpf_text_kprobe_body

    bpf_text += bpf_text_kprobe_header_openat
    bpf_text += bpf_text_kprobe_body

    if fnname_openat2:
        bpf_text += bpf_text_kprobe_header_openat2
        bpf_text += bpf_text_kprobe_body

if args.tid:  # TID trumps PID
    bpf_text = bpf_text.replace('PID_TID_FILTER',
        'if (tid != %s) { return 0; }' % args.tid)
elif args.pid:
    bpf_text = bpf_text.replace('PID_TID_FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('PID_TID_FILTER', '')
if args.uid:
    bpf_text = bpf_text.replace('UID_FILTER',
        'if (uid != %s) { return 0; }' % args.uid)
else:
    bpf_text = bpf_text.replace('UID_FILTER', '')
bpf_text = filter_by_containers(args) + bpf_text
if args.flag_filter:
    bpf_text = bpf_text.replace('FLAGS_FILTER',
        'if (!(flags & %d)) { return 0; }' % flag_filter_mask)
else:
    bpf_text = bpf_text.replace('FLAGS_FILTER', '')
if not (args.extended_fields or args.flag_filter):
    bpf_text = '\n'.join(x for x in bpf_text.split('\n')
        if 'EXTENDED_STRUCT_MEMBER' not in x)

if args.full_path:
    bpf_text = bpf_text.replace('SUBMIT_DATA', """
    data.type = EVENT_ENTRY;
    events.perf_submit(ctx, &data, sizeof(data));

    if (data.name[0] != '/') { // relative path
        struct task_struct *task;
        struct dentry *dentry;
        int i;

        task = (struct task_struct *)bpf_get_current_task_btf();
        dentry = task->fs->pwd.dentry;

        for (i = 1; i < MAX_ENTRIES; i++) {
            
            if (dentry == dentry->d_parent) { // root directory
                data.type = EVENT_MOUNTPOINT;
                data.mnt_dev = task->fs->pwd.mnt->mnt_sb->s_dev;
                events.perf_submit(ctx, &data, sizeof(data));
                break;
            }

            bpf_probe_read_kernel(&data.name, sizeof(data.name), (void *)dentry->d_name.name);
            data.type = EVENT_ENTRY;
            events.perf_submit(ctx, &data, sizeof(data));

            dentry = dentry->d_parent;
        }
    }

    data.type = EVENT_END;
    events.perf_submit(ctx, &data, sizeof(data));
    """)
else:
    bpf_text = bpf_text.replace('SUBMIT_DATA', """
    events.perf_submit(ctx, &data, sizeof(data));
    """)

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
if not is_support_kfunc:
    b.attach_kprobe(event=fnname_open, fn_name="syscall__trace_entry_open")
    b.attach_kretprobe(event=fnname_open, fn_name="trace_return")

    b.attach_kprobe(event=fnname_openat, fn_name="syscall__trace_entry_openat")
    b.attach_kretprobe(event=fnname_openat, fn_name="trace_return")

    if fnname_openat2:
        b.attach_kprobe(event=fnname_openat2, fn_name="syscall__trace_entry_openat2")
        b.attach_kretprobe(event=fnname_openat2, fn_name="trace_return")

initial_ts = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
print("%-6s %-16s %4s %3s " %
      ("TID" if args.tid else "PID", "COMM", "FD", "ERR"), end="")
if args.extended_fields:
    print("%-8s %-4s " % ("FLAGS", "MODE"), end="")
print("PATH")

class EventType(object):
    EVENT_ENTRY = 0
    EVENT_END = 1
    EVENT_MOUNTPOINT = 2

entries = defaultdict(list)

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    global initial_ts

    if not args.full_path or event.type == EventType.EVENT_END:
        skip = False

        # split return value into FD and errno columns
        if event.ret >= 0:
            fd_s = event.ret
            err = 0
        else:
            fd_s = -1
            err = - event.ret

        if not initial_ts:
            initial_ts = event.ts

        if args.failed and (event.ret >= 0):
            skip = True

        if args.name and bytes(args.name) not in event.comm:
            skip = True

        if not skip:
            if args.timestamp:
                delta = event.ts - initial_ts
                printb(b"%-14.9f" % (float(delta) / 1000000), nl="")

            if args.print_uid:
                printb(b"%-6d" % event.uid, nl="")

            printb(b"%-6d %-16s %4d %3d " %
                   (event.id & 0xffffffff if args.tid else event.id >> 32,
                    event.comm, fd_s, err), nl="")

            if args.extended_fields:
                # If neither O_CREAT nor O_TMPFILE is specified in flags, then
                # mode is ignored, see open(2).
                if event.mode == 0 and event.flags & os.O_CREAT == 0 and \
                   (event.flags & os.O_TMPFILE) != os.O_TMPFILE:
                    printb(b"%08o n/a  " % event.flags, nl="")
                else:
                    printb(b"%08o %04o " % (event.flags, event.mode), nl="")

            if not args.full_path:
                printb(b"%s" % event.name)
            else:
                paths = entries[event.id]
                paths.reverse()
                printb(b"%s" % os.path.join(*paths))


        if args.full_path:
            try:
                del(entries[event.id])
            except Exception:
                pass
    elif event.type == EventType.EVENT_ENTRY:
        entries[event.id].append(event.name)
    elif event.type == EventType.EVENT_MOUNTPOINT:
        dev_t = event.mnt_dev;
        # get mountpoint info from /proc/self/mountinfo
        with open("/proc/self/mountinfo", "r") as mountinfo:
            for line in mountinfo:
                parts = line.strip().split()
                major, minor = map(int, parts[2].split(":"))
                mountpoint = parts[4]
                line_dev_t = (major << 12) | minor # reconstruct an u32 from the major:minor components of the current line_dev_t.
                                                   # 12 bits according to linux/include/kdev_t.h "MAJOR"/"MINOR" macros
                if line_dev_t == dev_t:
                    entries[event.id].append(mountpoint.encode())

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=args.buffer_pages)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
