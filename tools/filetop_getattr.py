#!/usr/bin/env python3.6
# pylint: disable=no-absolute-import
#
# Copyright (c) 2021, Hudson River Trading LLC.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 21-Apr-2021   Guangyuan Yang       created this.

"""
filetop: Count VFS file getattr calls and summarize by process/file path.
---
examples:
  ./filetop                # run once, collect for 3 seconds
  ./filetop 5              # run once, collect for 5 seconds instead
  ./filetop -c nfsd        # run once, filter process name to nfsd only
  ./filetop -i -s getattr  # run in a loop, sort output by getattr
  ./filetop 10 -i -C       # run in a loop, 10 seconds refresh, don't clear the screen
"""

import os
import sys

import bcc

from bcc import topclass

# define BPF program
BPF_TEXT = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/mount.h>
#include <linux/fs_pin.h>

/*
 * XXX: struct mount is defined in fs/mount.h, which is not included in kernel
 * headers. So we duplicate the definition here.
 * The implementation may change across kernel versions, which should not affect
 * this BPF program as long as the fields that we extract information from do
 * not change. The below is from:
 * https://github.com/torvalds/linux/blob/v5.11/fs/mount.h#L39
 */
struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    union {
        struct rcu_head mnt_rcu;
        struct llist_node mnt_llist;
    };
#ifdef CONFIG_SMP
    struct mnt_pcp __percpu *mnt_pcp;
#else
    int mnt_count;
    int mnt_writers;
#endif
    struct list_head mnt_mounts;    /* list of children, anchored here */
    struct list_head mnt_child; /* and going through their mnt_child */
    struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
    const char *mnt_devname;    /* Name of device e.g. /dev/dsk/hda1 */
    struct list_head mnt_list;
    struct list_head mnt_expire;    /* link in fs-specific expiry list */
    struct list_head mnt_share; /* circular list of shared mounts */
    struct list_head mnt_slave_list;/* list of slave mounts */
    struct list_head mnt_slave; /* slave list entry */
    struct mount *mnt_master;   /* slave is on master->mnt_slave_list */
    struct mnt_namespace *mnt_ns;   /* containing namespace */
    struct mountpoint *mnt_mp;  /* where is it mounted */
    union {
        struct hlist_node mnt_mp_list;  /* list mounts with the same mountpoint */
        struct hlist_node mnt_umount;
    };
    struct list_head mnt_umounting; /* list entry for umount propagation */
#ifdef CONFIG_FSNOTIFY
    struct fsnotify_mark_connector __rcu *mnt_fsnotify_marks;
    __u32 mnt_fsnotify_mask;
#endif
    int mnt_id;         /* mount identifier */
    int mnt_group_id;       /* peer group identifier */
    int mnt_expiry_mark;        /* true if marked for expiry */
    struct hlist_head mnt_pins;
    struct hlist_head mnt_stuck_children;
};

/*
 * Helper macro to manipulate data structures
 */
#ifndef offsetof
#define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)
#endif

/*
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 */
#ifndef containerof
#define containerof(ptr, type, member) ({                      \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

// the key for the output summary
struct info_t {
    char comm[TASK_COMM_LEN];
    char name[_PATH_FILENAME_LEN_];

    u32 mnt_id;
    u8 is_path_part_truncated; // bool
    u8 is_filename_truncated; // bool

    _PATH_LEVEL_CHAR_DEF_
};

// the value of the output summary
struct val_t {
    u64 getattr;
};

BPF_HASH(filetop_counts, struct info_t, struct val_t, 102400 /* size */);

int trace_getattr_entry(struct pt_regs *ctx, const struct path *p,
    struct kstat *k, u32 d, unsigned int c)
{
    // filter process name
    _FILTER_COMM_BLOCK_

    // skip I/O lacking a filename
    struct dentry *de = p->dentry;
    struct qstr d_name = de->d_name; // variable reused later to save stack size
    bpf_probe_read_kernel(&d_name, sizeof(d_name), (void *)&de->d_name);
    if (d_name.len == 0)
        return 0;

    // store counts
    struct info_t info = {.is_path_part_truncated = 0, .is_filename_truncated = 0};
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    // find name
    if (d_name.len > _PATH_FILENAME_LEN_)
        info.is_filename_truncated = 1;
    bpf_probe_read_kernel(&info.name, sizeof(info.name), d_name.name);

    // find mountpoint
    struct vfsmount *vmnt;
    bpf_probe_read_kernel(&vmnt, sizeof(vmnt), &p->mnt);
    struct mount *real_mnt = containerof(vmnt, struct mount, mnt);
    bpf_probe_read_kernel(&info.mnt_id, sizeof(info.mnt_id), &real_mnt->mnt_id);

    // find path
    _FIND_PATH_BLOCK_

    struct val_t *valp, zero = {};
    valp = filetop_counts.lookup_or_try_init(&info, &zero);
    if (valp) {
        valp->getattr++;
    }
    return 0;
}

"""


# define all possible output columns here
COLUMN_FMT = {
    # info columns
    "comm": "{comm:<12}",
    "path": "{path:<40}",
    "is_truncated": "{is_truncated:<12}",
    # data columns
    "getattr": "{getattr:<8}",
    "getattr/s": "{getattr/s:<10}",
}


class FileTop(topclass.TopClass):
    """
    A class that inherits from TopClass to implement filetop.
    """

    def __init__(self):
        desc, epilog = __doc__.split("---")
        super().__init__(
            app_name="filetop",
            bpf_table="filetop_counts",
            desc=desc,
            epilog=epilog,
            column_fmt=COLUMN_FMT,
        )

        # this is populated by self.attach_kprobes()
        self.bpf = None

        # read and store mnt_id => mountpoint map
        # mountinfo fmt: https://www.kernel.org/doc/Documentation/filesystems/proc.txt
        self.mnt_id_map = {}
        with open("/proc/self/mountinfo", "r") as mi:
            for line in mi:
                l = line.split()
                self.mnt_id_map[int(l[0])] = l[4]

        # add arguments unique to this app
        self.arg_parser.add_argument(
            "-c", "--comm", help="trace this process name only"
        )
        self.arg_parser.add_argument(
            "-s",
            "--sort",
            default="nosort",
            choices=["getattr", "nosort"],
            help="sort by this column, default nosort",
        )
        self.arg_parser.add_argument(
            "-l",
            "--path.levels",
            type=int,
            default=20,
            dest="path_levels",
            help="max level of directories to go up. For paths that exceed (or \
                are equal to) the desired level, an ellipsis (...) will be shown \
                to indicate omission (e.g. /mnt/foo/...bar/baz).",
        )
        self.arg_parser.add_argument(
            "-fl",
            "--path.filename-length",
            type=int,
            default=48,
            dest="path_filename_length",
            help="max length of filename",
        )
        self.arg_parser.add_argument(
            "-pl",
            "--path.part-length",
            type=int,
            default=19,
            dest="path_part_length",
            help="max length of each part in path (excluding filename)",
        )

        self.args = self.arg_parser.parse_args()

    def attach_kprobes(self):
        """
        Implement necessary code generation, and attach kprobes.
        """
        bpf_text = BPF_TEXT

        # code generation for path level definition and finding
        find_path_levels_t = """
            cur = cur->d_parent;
            bpf_probe_read_kernel(&d_name, sizeof(d_name), (void *)&cur->d_name);
            if (d_name.len > _PATH_PART_LEN_)
                info.is_path_part_truncated = 1;
            bpf_probe_read_kernel(&info.path{i}, sizeof(info.path{i}), d_name.name);
        """

        init_char = ""
        find_path_levels = "struct dentry *cur = p->dentry;\n"

        for i in range(self.args.path_levels):
            init_char += f"char path{i}[{self.args.path_part_length}];\n"
            find_path_levels += find_path_levels_t.format(i=i)

        bpf_text = bpf_text.replace("_PATH_LEVEL_CHAR_DEF_", init_char)
        bpf_text = bpf_text.replace("_FIND_PATH_BLOCK_", find_path_levels)
        bpf_text = bpf_text.replace(
            "_PATH_FILENAME_LEN_", str(self.args.path_filename_length)
        )
        bpf_text = bpf_text.replace("_PATH_PART_LEN_", str(self.args.path_part_length))

        # code generation for filtering by comm
        filter_comm_t = """
            // Filter length is larger than what we're comparing with, so this
            // is definitely a mismatch. This condition can technically be
            // evaluated at the userspace when the program is first executed,
            // but we don't have access to TASK_COMM_LEN. That said, if we hit
            // this condition, we get 0 results, and the user should know why.
            if (_TARGET_COMM_SIZE_VAR_ >= TASK_COMM_LEN) {
                return 0;
            }
            // define local comm[] here to avoid initializing "struct info"
            // if this operation is filtered out
            char comm[TASK_COMM_LEN] = {0};
            bpf_get_current_comm(&comm, sizeof(comm));
            char target_comm[] = "_TARGET_COMM_VAR_";
            for (int i = 0; i < _TARGET_COMM_SIZE_VAR_; ++i) {
                // comm is shorter, so it has to be a mismatch.
                if (comm[i] == '\\0' || target_comm[i] != comm[i]) {
                    return 0;
                }
            }
            // handle the case where comm is longer than target_comm. Note that
            // target_comm[_TARGET_COMM_SIZE_VAR_] is \\0.
            if (comm[_TARGET_COMM_SIZE_VAR_] != '\\0') {
                return 0;
            }
        """
        filter_comm = ""
        if self.args.comm:
            filter_comm = filter_comm_t.replace("_TARGET_COMM_VAR_", self.args.comm)
            filter_comm = filter_comm.replace(
                "_TARGET_COMM_SIZE_VAR_",
                str(len(self.args.comm)),
            )
        bpf_text = bpf_text.replace("_FILTER_COMM_BLOCK_", filter_comm)

        # dry run option
        if self.args.dry_run:
            print(bpf_text)
            sys.exit()

        # initialize BPF
        self.bpf = bcc.BPF(text=bpf_text)
        self.bpf.attach_kprobe(event="vfs_getattr", fn_name="trace_getattr_entry")

    def output(self, counts_list: list):
        """
        Get and print desired output from BPF map.
        """
        # choose the columns to print
        self.printer.add_col("comm", "getattr", "getattr/s", "is_truncated", "path")

        # filter out entries where the count is zero, since we used
        # counts.zero() in top_output() which only zeros out the entries
        # in the BPF map.
        counts_list = [(k, v) for k, v in counts_list if v.getattr]

        # sort if self.args.sort is not "nosort"
        if self.args.sort != "nosort":

            def sort_getattr_fn(counts_list):
                return getattr(counts_list[1], "getattr")

            sort_mapping = {
                "getattr": sort_getattr_fn,
            }
            sort_fn = sort_mapping[self.args.sort]

            counts_list = sorted(counts_list, key=sort_fn, reverse=True)

        # limit the rows if self.args.maxrows is set
        if self.args.maxrows:
            counts_list = counts_list[: self.args.maxrows]

        # if measured true interval exists, use that instead
        if self.last_true_interval:
            interval = self.last_true_interval
        else:
            interval = self.args.interval

        # generate output
        for k, v in counts_list:
            # when walking up the dentry and reached "/", all d_parent
            # from there will be "/" itself, so we reconstruct the path
            # here
            path_tokens = []
            for i in range(self.args.path_levels - 1, -1, -1):
                path_tokens.append(getattr(k, f"path{i}").decode("utf-8", "replace"))
            filename = k.name.decode("utf-8", "replace")
            path_tokens.append(filename)

            # if the top of the path is not "/", it means we haven't
            # reached root
            if path_tokens[0] != "/":
                path_tokens[0] = "..." + path_tokens[0]

            # determine if path is truncated
            is_truncated = bool(
                k.is_filename_truncated
                or k.is_path_part_truncated
                or path_tokens[0].startswith("...")
            )

            # We want to have the boolean as-is for JSON output, and "Y"/"" for
            # text outputs. Ideally, this should be implemented in self.printer
            # since it is a formatting issue. Since it is the only case that we
            # are dealing with booleans, we try to handle this here to keep it
            # simple and explicit for now.
            if not self.args.json_lines_output:
                is_truncated = "Y" if is_truncated else ""

            path_str = os.path.join(path_tokens[0], *path_tokens[1:])

            # build the full path by prepending the mountpoint, the
            # leading `/` of path_str needs to be removed
            mnt_path_str = ""
            if k.mnt_id in self.mnt_id_map:
                mnt_path_str = self.mnt_id_map[k.mnt_id]
            full_path_str = os.path.join(mnt_path_str, path_str.strip(os.path.sep))

            info = {
                "comm": k.comm.decode("utf-8", "replace"),
                "getattr": v.getattr,
                "getattr/s": round(  # false positive pylint: disable=round-builtin
                    float(v.getattr) / interval,
                    2,
                ),
                "is_truncated": is_truncated,
                "path": full_path_str,
            }

            # add line
            self.printer.add_row_data(info)

        # print all added data
        self.printer.flush_all()


if __name__ == "__main__":

    FileTop().run()
