#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# slabratetop  Summarize kmem_cache_alloc/kmem_cache_free() calls.
#              For Linux, uses BCC, eBPF.
#
# USAGE: slabgrowth [-h] [-C] [-r MAXROWS] [interval] [count]
#
# This uses in-kernel BPF maps to store cache summaries for efficiency.
#
# SEE ALSO: slabgrowth(1), which monitors slab growth over time.
#
# Copyright 2021 B1-Systems GmbH.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 17-Nov-2021   Daniel Poelzleithner   Created this, based on slabtop
# 15-Oct-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import bcc
from bcc.utils import printb
from time import sleep, strftime, localtime
import argparse
from subprocess import call

# arguments
examples = """examples:
    ./slabgrowth            # kmem_cache_alloc() top, 1 second refresh
    ./slabgrowth -C         # don't clear the screen
    ./slabgrowth 5          # 5 second summaries
    ./slabgrowth 5 10       # 5 second summaries, 10 times only
"""
parser = argparse.ArgumentParser(
    description="Kernel SLAB/SLUB memory cache allocation rate top",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("-r", "--maxrows", default=20,
    help="maximum rows to print, default 20")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=-1,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
interval = float(args.interval)
countdown = int(args.count)
maxrows = int(args.maxrows)
clear = not int(args.noclear)
debug = 0

# linux stats
loadavg = "/proc/loadavg"

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/kasan.h>


// memcg_cache_params is a part of kmem_cache, but is not publicly exposed in
// kernel versions 5.4 to 5.8.  Define an empty struct for it here to allow the
// bpf program to compile.  It has been completely removed in kernel version
// 5.9, but it does not hurt to have it here for versions 5.4 to 5.8.
struct memcg_cache_params {};

#ifdef CONFIG_SLUB
#include <linux/slub_def.h>
#else
#include <linux/slab_def.h>
#endif

#define CACHE_NAME_SIZE 32

// the key for the output summary
struct info_t {
    char name[CACHE_NAME_SIZE];
};

// the value of the output summary
struct val_t {
    u_int64_t count;
    u_int64_t size;
    int64_t diff_count;
    int64_t diff_size;
};

BPF_HASH(counts, struct info_t, struct val_t);

int kprobe__kmem_cache_alloc(struct pt_regs *ctx, struct kmem_cache *cachep)
{
    struct info_t info = {};
    const char *name = cachep->name;
    bpf_probe_read_kernel(&info.name, sizeof(info.name), name);

    struct val_t *valp, zero = {};
    valp = counts.lookup_or_try_init(&info, &zero);
    if (valp) {
        valp->count++;
        valp->diff_count++;
        valp->size += (int64_t)cachep->size;
        valp->diff_size += (int64_t)cachep->size;
    }

    return 0;
}

int kprobe__kmem_cache_free(struct pt_regs *ctx, struct kmem_cache *cachep)
{
    struct info_t info = {};
    const char *name = cachep->name;
    bpf_probe_read_kernel(&info.name, sizeof(info.name), name);

    struct val_t *valp, zero = {};
    valp = counts.lookup_or_try_init(&info, &zero);
    if (valp) {
        valp->diff_count--;
        valp->diff_size -= cachep->size;
    }
    return 0;
}

"""
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text, debug=debug and bcc.DEBUG_PREPROCESSOR or 0)

print('Tracing... Output every %d secs. Hit Ctrl-C to end' % interval)

# output
exiting = 0

COLUMNS = ('count', 'size', 'diff_count', 'diff_size')
COLUMNS = ('diff_size', 'diff_count', 'count', 'size')
TITLES = ("DIFF BYTES", "DIFF ALLOCS", "ALLOCS", "BYTES")

started = localtime()

while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    counts = b.get_table("counts")
    # by-TID output
    line = 0

    # calculate column sizes
    max_sizes = {}
    for k, v in reversed(sorted(counts.items(),
                                key=lambda counts: counts[1].diff_size)):
        for i,col in enumerate(COLUMNS):
            max_sizes[col] = max(max_sizes.get(col, max(6, len(TITLES[i]))), len(str(getattr(v, col))))
        line += 1
        if line >= maxrows:
            break
    line = 0

    # header
    if clear:
        call("clear")
    else:
        print()
    with open(loadavg) as stats:
        print("%-8s -> %-8s   loadavg: %s" % (strftime("%Y-%m-%d %H:%M:%S", started), strftime("%Y-%m-%d %H:%M:%S"), stats.read()))

        data = ["%-32s" % 'CACHE'] + [TITLES[i].rjust(max_sizes[col]) for i, col in enumerate(COLUMNS)]
        printb(" | ".join(data).encode('utf-8'))

    for k, v in reversed(sorted(counts.items(),
                                key=lambda counts: counts[1].diff_size)):
        data = ["%-32s" % k.name.decode('utf-8', 'replace')] + [str(getattr(v, col)).rjust(max_sizes[col]) for col in COLUMNS]
        #print(data)
        #printb(b"%-32s %6d %10d %6d %10d" % (k.name, v.count, v.size, v.diff_count, v.diff_size))
        printb(" | ".join(data).encode('utf-8'))

        line += 1
        if line >= maxrows:
            break
    # clear count and size fields
    for k,v in counts.items():
        v.count = 0
        v.size = 0
    # counts.clear()

    if countdown > 0:
        countdown -= 1
    if exiting or countdown == 0:
        print("Detaching...")
        exit()
