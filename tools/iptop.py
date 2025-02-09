#!/usr/bin/env python3.6
# pylint: disable=no-absolute-import
#
# Copyright (c) 2021, Hudson River Trading LLC.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 21-Apr-2021   Guangyuan Yang       created this.

"""
iptop: Count NFSv4 server getattr calls and summarize by IP/hostname.
---
examples:
  ./iptop                  # run once, capture NFSd v3+v4, collect for 3 seconds
  ./iptop 5 -4             # run once, capture NFSd v4 only, collect for 5 seconds
  ./iptop -n               # run once, do not perform reverse DNS lookup
  ./iptop -i -s getattr    # run in a loop, sort output by getattr
  ./iptop -i -C -r 20      # run in a loop, output 20 rows max, do not clear the screen
"""

import os.path
import socket
import struct
import sys

import bcc

from bcc import topclass

# define BPF program
BPF_TEXT = """
#include <uapi/linux/ptrace.h>
#include <linux/sunrpc/svc.h>

struct key_t {
    u64 ip;
    u16 ss_family;
};

BPF_HASH(iptop_counts, struct key_t);

int trace_getattr_ip(struct pt_regs *ctx, struct svc_rqst *rqstp) {
    struct key_t key = {};
    struct sockaddr_in rq_addr;

    key.ss_family = rqstp->rq_addr.ss_family;
    bpf_probe_read_kernel(&rq_addr, sizeof(rq_addr), &rqstp->rq_addr);

    key.ip = rq_addr.sin_addr.s_addr;
    iptop_counts.increment(key);

    return 0;
}

"""


# define all possible output elements here
COLUMN_FMT = {
    # info columns
    "ip": "{ip:<16}",
    "hostname": "{hostname:<40}",
    # data columns
    "getattr": "{getattr:<8}",
    "getattr/s": "{getattr/s:<10}",
}


class IPTop(topclass.TopClass):
    """
    A class that inherits from TopClass to implement iptop.
    """

    def __init__(self):
        desc, epilog = __doc__.split("---")
        super().__init__(
            app_name="iptop",
            bpf_table="iptop_counts",
            desc=desc,
            epilog=epilog,
            column_fmt=COLUMN_FMT,
        )

        # this is populated by self.attach_kprobes()
        self.bpf = None

        # cache reverse DNS lookup results between runs
        self._hostname_cache = {}

        # add arguments unique to this app
        self.arg_parser.add_argument(
            "-n",
            "--no-lookup",
            action="store_true",
            help="do not do DNS reverse lookup",
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
            self.bpf.attach_kprobe(event="nfsd3_proc_getattr", fn_name="trace_getattr_ip")
        if self.args.v4:
            self.bpf.attach_kprobe(event="nfsd4_getattr", fn_name="trace_getattr_ip")

    def output(self, counts_list: list):
        """
        Get and print desired output from BPF map.
        """
        # choose the columns to print
        self.printer.add_col("ip", "getattr", "getattr/s")
        lookup = not self.args.no_lookup
        if lookup:
            self.printer.add_col("hostname")

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

        # generate output
        for k, v in counts_list:
            ip_str = socket.inet_ntoa(struct.pack("!I", k.ip))
            # for some reason, ip is reverted
            ip_str = ".".join(reversed(ip_str.split(".")))

            # reverse DNS lookup
            host_str = ""
            if lookup:
                # if interactive mode, utilize the cache
                # socket.getnameinfo() will not fail or block, it
                # simply return with the input ip if cannot find.
                if self.args.interactive:
                    if ip_str in self._hostname_cache:
                        host_str = self._hostname_cache[ip_str]
                    else:
                        host_str = socket.getnameinfo((ip_str, 0), 0)[0]
                        self._hostname_cache[ip_str] = host_str
                else:
                    host_str = socket.getnameinfo((ip_str, 0), 0)[0]

            info = {
                "ip": ip_str,
                "getattr": v.value,
                "getattr/s": "{:.2f}".format(
                    float(v.value)  # false positive pylint: disable=old-division
                    / interval
                ),
                "hostname": host_str,
            }

            # add the line
            self.printer.add_row_data(info)

        # print all added data
        self.printer.flush_all()


if __name__ == "__main__":

    IPTop().run()
