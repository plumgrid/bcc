#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# dirwatch Monitor directory file create and remove.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# Copyright 2023 CESTC, Co.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 23-Aug-2023    Rong Tao    Create this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import argparse
import os
from time import strftime

# arguments
examples = """
    ./dirwatch -D /etc         # trace file create/remove under /etc
    ./dirwatch -D /etc -V      # same as above, print more information(ppid,pcomm)
"""
parser = argparse.ArgumentParser(
    description="Monitor the creation and deletion of files under a directory",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-D", "--directory", default="-1",
    help="specify directory to watch")
parser.add_argument("-V", "--verbose", action="store_true",
    help="show file/directory create and remove, and show parent task pid/comm.")

args = parser.parse_args()
directory = args.directory
verbose = args.verbose

bpf_text = """
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>

enum op {
    OP_NULL,
    OP_UNLINK,  // 1
    OP_CREATE,  // 2
    OP_MKDIR,   // 3
    OP_RMDIR,   // 4
    OP_UNKNOWN,
};

struct my_data {
    u32 ppid;
    u32 pid;
    char pcomm[TASK_COMM_LEN];
    char comm[TASK_COMM_LEN];
    u64 parent_ino;
    u64 ino;
    enum op op;
    /* For OP_CREATE, OP_MKDIR */
    char fname[DNAME_INLINE_LEN];

    /* private */
    void *dir, *dentry;
};

BPF_PERF_OUTPUT(inode_events);
BPF_HASH(events_hash, u32, struct my_data);


static int record_event(struct pt_regs *ctx, enum op op,
                              struct inode *dir, struct dentry *dentry)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct my_data data = {};

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();;
    struct task_struct *parent;
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read(&data.ppid, sizeof(data.ppid), &parent->pid);
    bpf_probe_read(&data.pcomm, sizeof(data.pcomm), parent->comm);

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.pid = pid;
    data.op = op;
    data.dir = dir;
    data.dentry = dentry;

    /**
     * Unlink/Rmdir: use dir and dentry when kprobe, not kretprobe
     */
    if (op == OP_RMDIR || op == OP_UNLINK) {
        struct inode *inode = dentry->d_inode;
        /* Skip negative */
        if (!inode)
            return 0;

        data.parent_ino = dir->i_ino;
        data.ino = inode->i_ino;
    }

    events_hash.update(&tid, &data);

    return 0;
}

static int submit_event(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct my_data *info;

    info = events_hash.lookup(&tid);
    if (!info)
        return 0;

    events_hash.delete(&tid);

    /* skip failed */
    if (ret)
        return 0;

    enum op op = info->op;

    /**
     * Create/Mkdir refresh dir and dentry, get info when kretprobe
     */
    if (op == OP_CREATE || op == OP_MKDIR) {
        struct inode *dir = (struct inode *)info->dir;
        struct dentry *dentry = (struct dentry *)info->dentry;

        struct inode *inode = dentry->d_inode;
        /* Skip negative */
        if (!inode)
            return 0;

        info->parent_ino = dir->i_ino;
        info->ino = inode->i_ino;

        struct qstr d_name = dentry->d_name;
        if (d_name.len == 0)
            goto submit;
        bpf_probe_read_kernel(&info->fname, sizeof(info->fname), d_name.name);
    }

submit:
    inode_events.perf_submit(ctx, info, sizeof(*info));
    return 0;
}

TRACE_UNLINK
{
    return record_event(ctx, OP_UNLINK, dir, dentry);
}

TRACE_CREATE
{
    return record_event(ctx, OP_CREATE, dir, dentry);
}

/* dentry->d_inode == NULL here, non-null value when vfs_mkdir() return */
TRACE_MKDIR
{
    return record_event(ctx, OP_MKDIR, dir, dentry);
}

TRACE_RMDIR
{
    return record_event(ctx, OP_RMDIR, dir, dentry);
}

int trace_open(struct pt_regs *ctx, struct path *path, struct file *file)
{
    struct dentry *dentry = path->dentry;
    if (!(file->f_mode & FMODE_CREATED))
        return 0;
    /* Find parent inode. */
    struct inode *dir = path->dentry->d_parent->d_inode;
    return record_event(ctx, OP_CREATE, dir, dentry);
}

int trace_return(struct pt_regs *ctx)
{
    return submit_event(ctx);
}
"""

# Oldest one
trace_unlink_func_1="""
int trace_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
"""
trace_create_func_1="""
int trace_create(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
"""
trace_mkdir_func_1="""
int trace_mkdir(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
"""
trace_rmdir_func_1="""
int trace_rmdir(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
"""

# kernel commit 6521f8917082("namei: prepare for idmapped mounts") add argument
# 'struct user_namespace'.
trace_unlink_func_2="""
int trace_unlink(struct pt_regs *ctx, struct user_namespace *mnt_userns,
                 struct inode *dir, struct dentry *dentry)
"""
trace_create_func_2="""
int trace_create(struct pt_regs *ctx, struct user_namespace *mnt_userns,
                 struct inode *dir, struct dentry *dentry)
"""
trace_mkdir_func_2="""
int trace_mkdir(struct pt_regs *ctx, struct user_namespace *mnt_userns,
                 struct inode *dir, struct dentry *dentry)
"""
trace_rmdir_func_2="""
int trace_rmdir(struct pt_regs *ctx, struct user_namespace *mnt_userns,
                 struct inode *dir, struct dentry *dentry)
"""

# kernel commit abf08576afe3("fs: port vfs_*() helpers to struct mnt_idmap")
# use mnt_idmap instead of user_namespace.
trace_unlink_func_3="""
int trace_unlink(struct pt_regs *ctx, struct mnt_idmap *idmap,
                 struct inode *dir, struct dentry *dentry)
"""
trace_create_func_3="""
int trace_create(struct pt_regs *ctx, struct mnt_idmap *idmap,
                 struct inode *dir, struct dentry *dentry)
"""
trace_mkdir_func_3="""
int trace_mkdir(struct pt_regs *ctx, struct mnt_idmap *idmap,
                 struct inode *dir, struct dentry *dentry)
"""
trace_rmdir_func_3="""
int trace_rmdir(struct pt_regs *ctx, struct mnt_idmap *idmap,
                 struct inode *dir, struct dentry *dentry)
"""

# Store inode:pathname key value pairs.
hash_ino_file = {}
root_dir_ino = 0
poll_running = True

operate_string = {}
operate_string[1] = b'UNLINK'
operate_string[2] = b'CREATE'
operate_string[3] = b'MKDIR'
operate_string[4] = b'RMDIR'


def file_info(pathname):
    info = os.stat(pathname)
    if verbose:
        print("%s ino %d" % (pathname, info.st_ino))
    hash_ino_file[info.st_ino] = pathname


def recursive_listdir(path):
    files = os.listdir(path)

    file_info(path)

    for file in files:
        file_path = os.path.join(path, file)

        if os.path.islink(file_path):
            if not os.path.exists(os.readlink(file_path)):
                continue

        if os.path.isfile(file_path):
            file_info(file_path)
        elif os.path.islink(file_path):
            file_info(file_path)
            continue
        elif os.path.isdir(file_path):
            file_info(file_path)
            recursive_listdir(file_path)


def printb_event(event, filename):
    printb(b"%-8s " % strftime("%H:%M:%S").encode('ascii'), nl='')
    if verbose:
        printb(b"%-8d %-16s " % (event.ppid, event.pcomm), nl='')
    printb(b"%-8d %-16s %-8s %-12d %-16s" %
            (event.pid,
            event.comm,
            operate_string[event.op],
            event.ino,
            filename))


def handle_inode_event(cpu, data, size):
    event = b["inode_events"].event(data)
    global poll_running
    if event.op == 1 or event.op == 4: # unlink, rmdir
        if hash_ino_file.get(event.ino):
            printb_event(event, hash_ino_file[event.ino].encode('ascii'))
            # Remove from hash
            hash_ino_file.pop(event.ino)
        elif verbose:
            # Never call here
            printb_event(event, b'?????')
        # Root directory be removed
        if root_dir_ino == event.ino:
            print("Root directory %s be removed." % directory)
            poll_running = False
    elif event.op == 2 or event.op == 3: # create, mkdir
        # Create file under directory
        if hash_ino_file.get(event.parent_ino):
            if verbose:
                print("Create %s in %s" %
                      (str(event.fname, 'utf-8'),
                       hash_ino_file[event.parent_ino]))
            # Update hash
            hash_ino_file[event.ino] = "%s/%s" % \
                        (hash_ino_file[event.parent_ino],
                         str(event.fname,'utf-8'))

            printb_event(event, hash_ino_file[event.ino].encode('ascii'))
        elif verbose:
            # Never call here
            printb_event(event, b'?????')


if directory == "-1":
    print("Must specify a directory with -D, --directory")
    exit()
if not os.path.exists(directory):
    print("%s is not exist" % directory)
    exit()
if not os.path.isdir(directory):
    print("%s is not directory" % directory)
    exit()

# Get root directory inode number
root_dir_stat = os.stat(directory)
if verbose:
    print("%s ino %d" % (directory, root_dir_stat.st_ino))
root_dir_ino = root_dir_stat.st_ino

recursive_listdir(directory)
if verbose:
    print(hash_ino_file)

if BPF.kernel_struct_has_field(b'renamedata', b'new_mnt_idmap') == 1:
    bpf_text = bpf_text.replace('TRACE_UNLINK', trace_unlink_func_3)
    bpf_text = bpf_text.replace('TRACE_CREATE', trace_create_func_3)
    bpf_text = bpf_text.replace('TRACE_MKDIR', trace_mkdir_func_3)
    bpf_text = bpf_text.replace('TRACE_RMDIR', trace_rmdir_func_3)
elif BPF.kernel_struct_has_field(b'renamedata', b'old_mnt_userns') == 1:
    bpf_text = bpf_text.replace('TRACE_UNLINK', trace_unlink_func_2)
    bpf_text = bpf_text.replace('TRACE_CREATE', trace_create_func_2)
    bpf_text = bpf_text.replace('TRACE_MKDIR', trace_mkdir_func_2)
    bpf_text = bpf_text.replace('TRACE_RMDIR', trace_rmdir_func_2)
else:
    bpf_text = bpf_text.replace('TRACE_UNLINK', trace_unlink_func_1)
    bpf_text = bpf_text.replace('TRACE_CREATE', trace_create_func_1)
    bpf_text = bpf_text.replace('TRACE_MKDIR', trace_mkdir_func_1)
    bpf_text = bpf_text.replace('TRACE_RMDIR', trace_rmdir_func_1)

b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_unlink", fn_name="trace_unlink")
b.attach_kprobe(event="vfs_create", fn_name="trace_create")
b.attach_kprobe(event="vfs_open", fn_name="trace_open")
b.attach_kprobe(event="vfs_mkdir", fn_name="trace_mkdir")
b.attach_kprobe(event="vfs_rmdir", fn_name="trace_rmdir")

b.attach_kretprobe(event="vfs_unlink", fn_name="trace_return")
b.attach_kretprobe(event="vfs_create", fn_name="trace_return")
b.attach_kretprobe(event="vfs_open", fn_name="trace_return")
b.attach_kretprobe(event="vfs_mkdir", fn_name="trace_return");
b.attach_kretprobe(event="vfs_rmdir", fn_name="trace_return");

print("Tracing file remove ... Hit Ctrl-C to end")
print("%-8s " % "TIME", end='')
if verbose:
    print("%-8s %-16s " % ("PPID", "PCOMM"), end='')
print("%-8s %-16s %-8s %-12s %-16s" %
        ("PID", "COMM", "OPERATE", "INODE", "FILEPATH"))
b["inode_events"].open_perf_buffer(handle_inode_event)

while poll_running:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
