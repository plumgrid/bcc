#!/usr/bin/env python3.6
# pylint: disable=no-absolute-import
#
# Copyright (c) 2021, Hudson River Trading LLC.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 21-Apr-2021   Guangyuan Yang       created this.

"""
usertop: Count NFSv4 server getattr calls and summarize by uid/username.
---
examples:
  ./usertop                  # run once, capture NFSd v3+v4, collect for 3 seconds
  ./usertop 5 -4             # run once, capture NFSd v4 only, collect for 5 seconds
  ./usertop -n               # run once, do not perform uid to name lookup
  ./usertop -i -s getattr    # run in a loop, sort output by getattr
  ./usertop -i -C -r 20      # run in a loop, output 20 rows max, don't clear the screen
"""

import os.path
import pwd
import sys

import bcc

from bcc import topclass

# define BPF program
BPF_TEXT = """
#include <uapi/linux/ptrace.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/svcauth.h>

struct key_t {
    u32 uid;
};

BPF_HASH(usertop_counts, struct key_t);

int trace_getattr_uid(struct pt_regs *ctx, struct svc_rqst *rqstp) {
    struct key_t key = {};
    bpf_probe_read_kernel(&key.uid, sizeof(key.uid), &rqstp->rq_cred.cr_uid);
    usertop_counts.increment(key);
    return 0;
}

"""


# define all possible output elements here
COLUMN_FMT = {
    # info columns
    "uid": "{uid:<8}",
    "unix": "{unix:<15}",
    # data columns
    "getattr": "{getattr:<8}",
    "getattr/s": "{getattr/s:<10}",
}


class UserTop(topclass.TopClass):
    """
    A class that inherits from TopClass to implement usertop.
    """

    def __init__(self):
        desc, epilog = __doc__.split("---")
        super().__init__(
            app_name="usertop",
            bpf_table="usertop_counts",
            desc=desc,
            epilog=epilog,
            column_fmt=COLUMN_FMT,
        )

        # this is populated by self.attach_kprobes()
        self.bpf = None

        self.arg_parser.add_argument(
            "-n",
            "--no-lookup",
            action="store_true",
            help="do not do uid to name lookup",
        )
        self.arg_parser.add_argument(
            "-s",
            "--sort",
            default="nosort",
            choices=["getattr", "nosort"],
            help="sort by this column",
        )
        self.arg_parser.add_argument(
            "-3",
            dest="v3",
            action="store_true",
            help="capture NFSd v3 calls only, default to v3+v4 if neither is specified",
        )
        self.arg_parser.add_argument(
            "-4",
            dest="v4",
            action="store_true",
            help="capture NFSd v4 calls only, default to v3+v4 if neither is specified",
        )

        self.args = self.arg_parser.parse_args()

        # if NFSd version is not specified, capture both
        if not self.args.v3 and not self.args.v4:
            self.args.v3 = True
            self.args.v4 = True

    def attach_kprobes(self):
        """
        Attach kprobes.
        """
        # dry run option
        if self.args.dry_run:
            print(BPF_TEXT)
            sys.exit()

        # initialize BPF
        self.bpf = bcc.BPF(text=BPF_TEXT)

        # attach based on the NFSd version specified
        if self.args.v3:
            self.bpf.attach_kprobe(event="nfsd3_proc_getattr", fn_name="trace_getattr_uid")
        if self.args.v4:
            self.bpf.attach_kprobe(event="nfsd4_getattr", fn_name="trace_getattr_uid")

    def output(self, counts_list: list):
        """
        Get and print desired output from BPF map.
        """
        # choose the columns to print
        self.printer.add_col("uid", "unix", "getattr", "getattr/s")

        # filter out entries where the count is zero, since we used
        # counts.zero in top_output().
        counts_list = [(k, v) for k, v in counts_list if v.value]

        # sort if self.args.sort is not "nosort"
        if self.args.sort != "nosort":

            def sort_fn(counts_list):
                return getattr(counts_list[1], "value")

            counts_list = sorted(counts_list, key=sort_fn, reverse=True)

        # limit the rows if self.args.maxrows is set
        if self.args.maxrows:
            counts_list = counts_list[: self.args.maxrows]

        # if measured true interval exists, use that instead
        if self.last_true_interval:
            interval = self.last_true_interval
        else:
            interval = self.args.interval

        for k, v in counts_list:
            try:
                unix = pwd.getpwuid(k.uid).pw_name
            except KeyError:
                unix = ""

            info = {
                "uid": k.uid,
                "unix": unix,
                "getattr": v.value,
                "getattr/s": "{:.2f}".format(
                    float(v.value)  # false positive pylint: disable=old-division
                    / interval
                ),
            }

            # add the line
            self.printer.add_row_data(info)

        # print all added data
        self.printer.flush_all()


if __name__ == "__main__":

    UserTop().run()
