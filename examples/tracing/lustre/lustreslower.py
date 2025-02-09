#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# lustreslower  Trace slow lustre operations.
#            For Linux, uses BCC, eBPF.
#
# USAGE: lustreslower [-h] [-j] [-p PID] [min_ms]
#
# This script traces common lustre file operations: reads, writes, opens,
# syncs and getattr. It measures the time spent in these operations, and prints details
# for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to these lustre operations,
# including reads and writes from the file system cache. Such reads and writes
# can be very frequent (depending on the workload; eg, 1M/sec), at which
# point the overhead of this tool (even if it prints no "slower" events) can
# begin to become significant.
#
# By default, a minimum millisecond threshold of 10 is used.
#
# 15-Aug-2020   Gu Zheng  Created this. Should work with lustre v2.12+


from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# symbols
kallsyms = "/proc/kallsyms"

# arguments
examples = """examples:
    ./lustreslower             # trace operations slower than 10 ms (default)
    ./lustreslower 1           # trace operations slower than 1 ms
    ./lustreslower -j 1        # ... 1 ms, parsable output (csv)
    ./lustreslower 0           # trace all operations (warning: verbose)
    ./lustreslower -p 185      # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Trace common lustre file operations slower than a threshold",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-j", "--csv", action="store_true",
    help="just print fields: comma-separated values")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("min_ms", nargs="?", default='10',
    help="minimum I/O duration to trace, in ms (default 10)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
min_ms = int(args.min_ms)
pid = args.pid
csv = args.csv
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>

// XXX: switch these to char's when supported
#define TRACE_READ      0
#define TRACE_WRITE     1
#define TRACE_OPEN      2
#define TRACE_FSYNC     3
#define TRACE_GETATTR   4

struct val_t {
    u64 ts;
    u64 offset;
    struct file *fp;
    struct dentry *d;
};

struct data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 type;
    u64 size;
    u64 offset;
    u64 delta_us;
    u64 pid;
    char task[TASK_COMM_LEN];
    char file[DNAME_INLINE_LEN];
};

BPF_HASH(entryinfo, u64, struct val_t);
BPF_PERF_OUTPUT(events);

//
// Store timestamp and size on entry
//

// new_sync_read/write() ll_file_read_iter(), ll_file_write_iter():
LUSTRE_NEW_SYNC_RW_TRACE

int trace_rw_entry(struct pt_regs *ctx, struct kiocb *iocb)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = iocb->ki_filp;
    val.offset = iocb->ki_pos;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

// ll_file_open():
int trace_open_entry(struct pt_regs *ctx, struct inode *inode,
    struct file *file)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = file;
    val.offset = 0;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

// ll_fsync():
int trace_fsync_entry(struct pt_regs *ctx, struct file *file)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = file;
    val.offset = 0;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

LUSTRE_GETATTR_TRACE

//
// Output
//

static int trace_return(struct pt_regs *ctx, int type)
{
    struct val_t *valp;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    valp = entryinfo.lookup(&id);
    if (valp == 0) {
        // missed tracing issue or filtered
        return 0;
    }

    // calculate delta
    u64 ts = bpf_ktime_get_ns();
    u64 delta_us = ts - valp->ts;
    entryinfo.delete(&id);

    // Skip entries with backwards time: temp workaround for #728
    if ((s64) delta_us < 0)
        return 0;

    delta_us /= 1000;

    if (FILTER_US)
        return 0;

    // populate output struct
    u32 size = PT_REGS_RC(ctx);
    struct data_t data = {.type = type, .size = size, .delta_us = delta_us,
        .pid = pid};
    data.ts_us = ts / 1000;
    data.offset = valp->offset;
    bpf_get_current_comm(&data.task, sizeof(data.task));

    // workaround (rewriter should handle file to d_name in one step):
    struct dentry *de = NULL;
    struct qstr qs = {};
    if(type == TRACE_GETATTR)
    {
        bpf_probe_read_kernel(&de, sizeof(de), &valp->d);
    }
    else
    {
        bpf_probe_read_kernel(&de, sizeof(de), &valp->fp->f_path.dentry);
    }

    bpf_probe_read_kernel(&qs, sizeof(qs), (void *)&de->d_name);
    if (qs.len == 0)
        return 0;

    bpf_probe_read_kernel(&data.file, sizeof(data.file), (void *)qs.name);

    // output
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int trace_read_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_READ);
}

int trace_write_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_WRITE);
}

int trace_open_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_OPEN);
}

int trace_fsync_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_FSYNC);
}

int trace_getattr_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_GETATTR);
}

"""

# To detect the proper function to trace check if
# new_sync_read/write() or ll_file_read/write_iter() is defined in /proc/kallsyms.
if BPF.get_kprobe_functions(b'll_file_read_iter'):
    lustre_read_fn = 'll_file_read_iter'
    lustre_trace_rw_fn = 'trace_rw_entry'
    lustre_trace_rw_code = ''
elif BPF.get_kprobe_functions(b'll_file_read'):
    lustre_read_fn = 'll_file_read'
    lustre_trace_rw_fn = 'trace_rw_entry'
    lustre_trace_rw_code = ''
else:
    lustre_read_fn = 'new_sync_read'
    lustre_trace_rw_fn = 'trace_new_sync_rw_entry'
    lustre_file_ops_addr = ''
    with open(kallsyms) as syms:
        for line in syms:
            (addr, size, name) = line.rstrip().split(" ", 2)
            name = name.split("\t")[0]
            if name == "ll_file_operations":
                lustre_file_ops_addr = "0x" + addr
                break
        if lustre_file_ops_addr == '':
            print("ERROR: no ll_file_operations in /proc/kallsyms. Exiting.")
            print("HINT: the kernel should be built with CONFIG_KALLSYMS_ALL.")
            exit()
    lustre_trace_rw_code = """
    int trace_new_sync_rw_entry(struct pt_regs *ctx, struct kiocb *iocb)
    {
        u64 id = bpf_get_current_pid_tgid();
        u32 pid = id >> 32; // PID is higher part

        if (FILTER_PID)
        return 0;

        // lustre filter on file->f_op == ll_file_operations
        struct file *fp = iocb->ki_filp;
        if ((u64)fp->f_op != %s)
            return 0;

        // store filep and timestamp by id
        struct val_t val = {};
        val.ts = bpf_ktime_get_ns();
        val.fp = iocb->ki_filp;
        val.offset = iocb->ki_pos;
        if (val.fp)
            entryinfo.update(&id, &val);

        return 0;
    }""" % lustre_file_ops_addr

lustre_trace_getattr_code = ''
with open(kallsyms) as syms:
    for line in syms:
        (addr, size, name) = line.rstrip().split(" ", 2)
        name = name.split("\t")[0]
        if name == "ll_file_inode_operations":
            lustre_inode_ops_addr = "0x" + addr
            break
    if lustre_inode_ops_addr == '':
        print("ERROR: no ll_file_inode_operations in /proc/kallsyms. Exiting.")
        print("HINT: the kernel should be built with CONFIG_KALLSYMS_ALL.")
        exit()
    lustre_trace_getattr_code = """
int trace_getattr_entry(struct pt_regs *ctx, const struct path *path,
                        struct kstat *kstat, u32 mask, unsigned int flags)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if(FILTER_PID)
        return 0;

    struct inode *ino = path->dentry->d_inode;
    if ((u64)ino->i_op != %s)
        return 0;

    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = NULL;
    val.d = path->dentry;
    val.offset = 0;
    if (val.d)
        entryinfo.update(&id, &val);

    return 0;
}""" % lustre_inode_ops_addr


if BPF.get_kprobe_functions(b'll_file_write_iter'):
    lustre_write_fn = 'll_file_write_iter'
elif BPF.get_kprobe_functions(b'll_file_write'):
    lustre_write_fn = 'll_file_write'
else:
    lustre_write_fn = 'new_sync_write'

bpf_text = bpf_text.replace('LUSTRE_NEW_SYNC_RW_TRACE', lustre_trace_rw_code)
bpf_text = bpf_text.replace('LUSTRE_GETATTR_TRACE', lustre_trace_getattr_code)
if min_ms == 0:
    bpf_text = bpf_text.replace('FILTER_US', '0')
else:
    bpf_text = bpf_text.replace('FILTER_US',
        'delta_us <= %s' % str(min_ms * 1000))
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    type = 'R'
    if event.type == 1:
        type = 'W'
    elif event.type == 2:
        type = 'O'
    elif event.type == 3:
        type = 'S'
    elif event.type == 4:
        type = 'G'

    if (csv):
        print("%d,%s,%d,%s,%d,%d,%d,%s" % (
            event.ts_us, event.task, event.pid, type, event.size,
            event.offset, event.delta_us, event.file))
        return
    print("%-8s %-14.14s %-6s %1s %-7s %-8d %7.2f %s" %
          (strftime("%H:%M:%S"),
           event.task.decode('utf-8', 'replace'),
           event.pid, type, event.size,
           event.offset / 1024,
           float(event.delta_us) / 1000,
           event.file.decode('utf-8', 'replace')))

# initialize BPF
b = BPF(text=bpf_text)


# common file functions
b.attach_kprobe(event=lustre_read_fn, fn_name=lustre_trace_rw_fn)
b.attach_kprobe(event=lustre_write_fn, fn_name=lustre_trace_rw_fn)
b.attach_kprobe(event="ll_file_open", fn_name="trace_open_entry")
b.attach_kprobe(event="ll_fsync", fn_name="trace_fsync_entry")
b.attach_kprobe(event="vfs_getattr", fn_name="trace_getattr_entry")
b.attach_kretprobe(event=lustre_read_fn, fn_name="trace_read_return")
b.attach_kretprobe(event=lustre_write_fn, fn_name="trace_write_return")
b.attach_kretprobe(event="ll_file_open", fn_name="trace_open_return")
b.attach_kretprobe(event="ll_fsync", fn_name="trace_fsync_return")
b.attach_kretprobe(event="vfs_getattr", fn_name="trace_getattr_return")

# header
if (csv):
    print("ENDTIME_us,TASK,PID,TYPE,BYTES,OFFSET_b,LATENCY_us,FILE")
else:
    if min_ms == 0:
        print("Tracing lustre operations")
    else:
        print("Tracing lustre operations slower than %d ms" % min_ms)
    print("%-8s %-14s %-6s %1s %-7s %-8s %7s %s" % ("TIME", "COMM", "PID", "T",
        "BYTES", "OFF_KB", "LAT(ms)", "FILENAME"))

# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
