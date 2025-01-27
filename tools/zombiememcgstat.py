#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# zombiememcgstat Dump info about zombie memcgroups
#           For Linux, uses BCC, eBPF.
#
# USAGE: zombiememcgstat [-h] [-p] [-c] [-o] [interval] [count]
#
# Copyright 2025 Oracle and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 01-Jan-2025   Imran Khan     Created this.


from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals
from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import sys

# arguments
examples = """examples:
    ./zombiememcgstat            # list all zombie memcgs at 30 secs interval
    ./zombiememcgstat 5          # list all zombie memcgs at 5 secs interval
    ./zombiememcgstat 30 10      # print 30 second summaries, 10 times
    ./zombiememcgstat -p 1       # list zombie memcgs created by pid 1
    ./zombiememcgstat -c systemd # list zombie memcgs created by systemd
    ./zombiememcgstat -o 600     # list zombie memcgs older than 600 secs
"""

parser = argparse.ArgumentParser(
    description="""
    Zombie memory cgroups (memcgs) are cgroups that have  been removed
    from user space but still exist in kernel space due to non-zero refcounts.
    List such zombie memcgs on a system along with their creator and
    offline duration.
    """,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int,
    help="show zombie memcgs created by specified pid")
parser.add_argument("-c", "--comm", type=str,
    help="show zombie memcgs created by specified comm")
parser.add_argument("-o", "--older", default=60, type=int,
    help="show zombie memcgs that are offline for more than these many secs.")
parser.add_argument("interval", nargs="?", default=30,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
min_offline_time = args.older
debug = 0

if args.pid and int(args.pid) <= 0:
    print("specified task pid should be greater than 0.")
    exit(-1)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h> /* For TASK_COMM_LEN */
#include <linux/memcontrol.h> /* For mem_cgroup_from_css */

#define MAX_NAME_LEN	(256)

typedef struct memcg_info {
    u64 online_ts;
    u64 offline_ts;
    u32 pid;
    u8 offline;
    char comm[TASK_COMM_LEN];
    char name[MAX_NAME_LEN];
    u64 memcg_ptr;
} memcg_info_t;

BPF_HASH(offline_memcg_info, u64, memcg_info_t);

static int cmp_comms(const char *comm1, const char *comm2, int len)
{
    unsigned char n1, n2;
    while (len-- > 0) {
        n1 = *comm1++;
        n2 = *comm2++;
        if (n1 != n2)
            return n1 - n2;
        if (!n1)
            break;
    }
    return 0;
}

int mem_cgroup_css_online_probe(struct pt_regs *ctx,
                                struct cgroup_subsys_state *css)
{
    struct kernfs_node *kn;
    struct mem_cgroup *memcg_ptr = (struct mem_cgroup *)PT_REGS_PARM1(ctx);
    memcg_info_t memcg_val = {};
    memcg_val.pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    bpf_get_current_comm(&memcg_val.comm, sizeof(memcg_val.comm));
    FILTER_COMM
    kn = memcg_ptr->css.cgroup->kn;
    bpf_probe_read_kernel_str(&memcg_val.name,
                              sizeof(memcg_val.name), kn->name);
    memcg_val.offline = 0;
    memcg_val.memcg_ptr = (u64)memcg_ptr;
    memcg_val.online_ts = bpf_ktime_get_ns();
    offline_memcg_info.update(&memcg_val.memcg_ptr, &memcg_val);
    return 0;
}

int mem_cgroup_css_offline_probe(struct pt_regs *ctx,
                                 struct cgroup_subsys_state *css)
{
    u64 memcg_ptr = (u64)PT_REGS_PARM1(ctx);
    memcg_info_t *memcg_val_p = offline_memcg_info.lookup(&memcg_ptr);
    if (memcg_val_p == 0) {
        return 0; //data absent
    }
    memcg_val_p->offline = 1;
    memcg_val_p->offline_ts = bpf_ktime_get_ns();
    return 0;
}

int mem_cgroup_css_free_probe(struct pt_regs *ctx,
                              struct cgroup_subsys_state *css)
{
    u64 memcg_ptr = (u64)PT_REGS_PARM1(ctx);
    offline_memcg_info.delete(&memcg_ptr);
    return 0;
}
"""

# code substitutions
if args.pid:
    filter_pid_text = """
    if (memcg_val.pid != %d) {
        return 0;
    }
    """ % (args.pid)
    bpf_text = bpf_text.replace('FILTER_PID', filter_pid_text)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '')

if args.comm:
    filter_comm_text = """
    if (cmp_comms(memcg_val.comm, "%s", TASK_COMM_LEN)) {
        return 0;
    }
    """ % (args.comm)
    bpf_text = bpf_text.replace('FILTER_COMM', filter_comm_text)
else:
    bpf_text = bpf_text.replace('FILTER_COMM', '')

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="mem_cgroup_css_online",
                fn_name="mem_cgroup_css_online_probe")
b.attach_kprobe(event="mem_cgroup_css_offline",
                fn_name="mem_cgroup_css_offline_probe")
b.attach_kprobe(event="mem_cgroup_css_free",
                fn_name="mem_cgroup_css_free_probe")

print("Show zombie memcgroups at specified intervals... Hit Ctrl-C to end.")

# header
print(f'{"MEMCG":<20} {"NAME":<22} {"COMM":<16} {"PID":<8} {"AGE(secs)":<8}')
# output
exiting = 0 if args.interval else 1
memcgs = b["offline_memcg_info"]
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    for address, info in sorted(memcgs.items(),
                                key=lambda memcgs: memcgs[1].offline_ts):
        try:
            if not info.offline:
                continue
            curr_time = BPF.monotonic_time()
            offline_age = (curr_time - info.offline_ts) // 1000000000
            if offline_age < min_offline_time:
                continue
            print("0x%-18x %-22s %-16s %-8d %-8d" %
                    (address.value, info.name.decode()[:22],
                     info.comm.decode()[:16], info.pid,
                     offline_age))
        except KeyboardInterrupt:
            exiting = 1

    countdown -= 1
    if exiting or countdown == 0:
        exit()
