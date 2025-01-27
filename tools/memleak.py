#!/usr/bin/env python
#
# memleak   Trace and display outstanding allocations to detect
#           memory leaks in user-mode processes and the kernel.
#
# USAGE: memleak [-h] [-p PID] [-t] [-a] [-o OLDER] [-c COMMAND]
#                [--combined-only] [--wa-missing-free] [-s SAMPLE_RATE]
#                [-T TOP] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJ]
#                [interval] [count]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF
from time import sleep
from datetime import datetime
import resource
import argparse
import subprocess
import os
import sys

class Allocation(object):
    def __init__(self, stack, size, type_index):
        self.stack = stack
        self.count = 1
        self.size = size
        self.type_index = type_index

    def update(self, size):
        self.count += 1
        self.size += size

def run_command_get_output(command):
        p = subprocess.Popen(command.split(),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return iter(p.stdout.readline, b'')

def run_command_get_pid(command):
        p = subprocess.Popen(command.split())
        return p.pid

sort_keys = ["size", "count"]
alloc_sort_map = {sort_keys[0]: lambda a: a.size,
                  sort_keys[1]: lambda a: a.count};
combined_sort_map = {sort_keys[0]: lambda a: -a[1].total_size,
                     sort_keys[1]: lambda a: -a[1].number_of_allocs};

examples = """
EXAMPLES:

./memleak -p $(pidof allocs)
        Trace allocations and display a summary of "leaked" (outstanding)
        allocations every 5 seconds
./memleak -p $(pidof allocs) -t
        Trace allocations and display each individual allocator function call
./memleak -ap $(pidof allocs) 10
        Trace allocations and display allocated addresses, sizes, and stacks
        every 10 seconds for outstanding allocations
./memleak -c "./allocs"
        Run the specified command and trace its allocations
./memleak
        Trace allocations in kernel mode and display a summary of outstanding
        allocations every 5 seconds
./memleak -o 60000
        Trace allocations in kernel mode and display a summary of outstanding
        allocations that are at least one minute (60 seconds) old
./memleak -s 5
        Trace roughly every 5th allocation, to reduce overhead
./memleak --sort count
        Trace allocations in kernel mode and display a summary of outstanding
        allocations that are sorted in count order
"""

description = """
Trace outstanding memory allocations that weren't freed.
Supports both user-mode allocations made with libc functions and kernel-mode
allocations made with kmalloc/kmem_cache_alloc/get_free_pages and corresponding
memory release functions.
"""

parser = argparse.ArgumentParser(description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-p", "--pid", type=int, default=-1,
        help="the PID to trace; if not specified, trace kernel allocs")
parser.add_argument("-t", "--trace", action="store_true",
        help="print trace messages for each alloc/free call")
parser.add_argument("interval", nargs="?", default=5, type=int,
        help="interval in seconds to print outstanding allocations")
parser.add_argument("count", nargs="?", type=int,
        help="number of times to print the report before exiting")
parser.add_argument("-a", "--show-allocs", default=False, action="store_true",
        help="show allocation addresses and sizes as well as call stacks")
parser.add_argument("-o", "--older", default=500, type=int,
        help="prune allocations younger than this age in milliseconds")
parser.add_argument("-c", "--command",
        help="execute and trace the specified command")
parser.add_argument("--combined-only", default=False, action="store_true",
        help="show combined allocation statistics only")
parser.add_argument("--wa-missing-free", default=False, action="store_true",
        help="Workaround to alleviate misjudgments when free is missing")
parser.add_argument("-s", "--sample-rate", default=1, type=int,
        help="sample every N-th allocation to decrease the overhead")
parser.add_argument("-T", "--top", type=int, default=10,
        help="display only this many top allocating stacks (by size)")
parser.add_argument("-z", "--min-size", type=int,
        help="capture only allocations larger than or equal to this size")
parser.add_argument("-Z", "--max-size", type=int,
        help="capture only allocations smaller than or equal to this size")
parser.add_argument("-O", "--obj", type=str, default="c",
        help="attach to allocator functions in the specified object")
parser.add_argument("--ebpf", action="store_true",
        help=argparse.SUPPRESS)
parser.add_argument("--percpu", default=False, action="store_true",
        help="trace percpu allocations")
parser.add_argument("--sort", type=str, default="size",
        help="report sorted in given key; available key list: size, count")
parser.add_argument("--symbols-prefix", type=str,
        help="memory allocator symbols prefix")

args = parser.parse_args()

pid = args.pid
command = args.command
kernel_trace = (pid == -1 and command is None)
trace_all = args.trace
interval = args.interval
min_age_ns = 1e6 * args.older
sample_every_n = args.sample_rate
num_prints = args.count
top_stacks = args.top
min_size = args.min_size
max_size = args.max_size
obj = args.obj
sort_key = args.sort

if sort_key not in sort_keys:
        print("Given sort_key:", sort_key)
        print("Supporting sort key list:", sort_keys)
        exit(1)

if min_size is not None and max_size is not None and min_size > max_size:
        print("min_size (-z) can't be greater than max_size (-Z)")
        exit(1)

if command is not None:
        print("Executing '%s' and tracing the resulting process." % command)
        pid = run_command_get_pid(command)

bpf_source = """
#include <uapi/linux/ptrace.h>

struct alloc_info_t {
        u64 size;
        u64 timestamp_ns;
        int stack_id;
        u32 type_index;
};

struct combined_alloc_info_t {
        u64 total_size;
        u64 number_of_allocs;
};

#define KERNEL 0
#define MALLOC 1
#define CALLOC 2
#define REALLOC 3
#define MMAP 4
#define POSIX_MEMALIGN 5
#define VALLOC 6
#define MEMALIGN 7
#define PVALLOC 8
#define ALIGNED_ALLOC 9
#define FREE 10
#define MUNMAP 11

BPF_HASH(sizes, u64, u64);
BPF_HASH(allocs, u64, struct alloc_info_t, 1000000);
BPF_HASH(memptrs, u32, u64);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_HASH(combined_allocs, u64, struct combined_alloc_info_t, 10240);

static inline void update_statistics_add(u64 stack_id, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0, 0};

        existing_cinfo = combined_allocs.lookup(&stack_id);
        if (!existing_cinfo) {
                combined_allocs.update(&stack_id, &cinfo);
                existing_cinfo = combined_allocs.lookup(&stack_id);
                if (!existing_cinfo)
                        return;
        }
        __sync_fetch_and_add(&existing_cinfo->total_size, sz);
        __sync_fetch_and_add(&existing_cinfo->number_of_allocs, 1);
}

static inline void update_statistics_del(u64 stack_id, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;

        existing_cinfo = combined_allocs.lookup(&stack_id);
        if (!existing_cinfo)
                return;

        if (existing_cinfo->number_of_allocs > 1) {
                __sync_fetch_and_sub(&existing_cinfo->total_size, sz);
                __sync_fetch_and_sub(&existing_cinfo->number_of_allocs, 1);
        } else {
                combined_allocs.delete(&stack_id);
        }
}

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size, u32 type_index) {
        SIZE_FILTER
        if (SAMPLE_EVERY_N > 1) {
                u64 ts = bpf_ktime_get_ns();
                if (ts % SAMPLE_EVERY_N != 0)
                        return 0;
        }

        u32 tid = bpf_get_current_pid_tgid();
        u64 size64 = size;
        u64 key = (uint64_t)type_index << 32 | tid;
        sizes.update(&key, &size64);

        if (SHOULD_PRINT)
                bpf_trace_printk("alloc entered, size = %u\\n", size);
        return 0;
}

static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address, u32 type_index) {
        u32 tid = bpf_get_current_pid_tgid();
        u64 key = (uint64_t)type_index << 32 | tid;
        u64* size64 = sizes.lookup(&key);
        struct alloc_info_t info = {0};

        if (size64 == 0)
                return 0; // missed alloc entry

        info.size = *size64;
        sizes.delete(&key);

        if (address != 0) {
                info.timestamp_ns = bpf_ktime_get_ns();
                info.stack_id = stack_traces.get_stackid(ctx, STACK_FLAGS);
                info.type_index = type_index
                allocs.update(&address, &info);
                update_statistics_add(info.stack_id, info.size);
        }

        if (SHOULD_PRINT) {
                bpf_trace_printk("alloc exited, size = %lu, result = %lx\\n",
                                 info.size, address);
        }
        return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx, u32 type_index) {
        return gen_alloc_exit2(ctx, PT_REGS_RC(ctx), type_index);
}

static inline int gen_free_enter(struct pt_regs *ctx, void *address) {
        u64 addr = (u64)address;
        struct alloc_info_t *info = allocs.lookup(&addr);
        if (info == 0)
                return 0;

        allocs.delete(&addr);
        update_statistics_del(info->stack_id, info->size);

        if (SHOULD_PRINT) {
                bpf_trace_printk("free entered, address = %lx, size = %lu\\n",
                                 address, info->size);
        }
        return 0;
}

int malloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size, MALLOC);
}

int malloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit2(ctx, PT_REGS_RC(ctx), MALLOC);
}

int free_enter(struct pt_regs *ctx, void *address) {
        return gen_free_enter(ctx, address);
}

int calloc_enter(struct pt_regs *ctx, size_t nmemb, size_t size) {
        return gen_alloc_enter(ctx, nmemb * size, CALLOC);
}

int calloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx, CALLOC);
}

int realloc_enter(struct pt_regs *ctx, void *ptr, size_t size) {
        gen_free_enter(ctx, ptr);
        return gen_alloc_enter(ctx, size, REALLOC);
}

int realloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx, REALLOC);
}

int mmap_enter(struct pt_regs *ctx) {
        size_t size = (size_t)PT_REGS_PARM2(ctx);
        return gen_alloc_enter(ctx, size, MMAP);
}

int mmap_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx, MMAP);
}

int munmap_enter(struct pt_regs *ctx, void *address) {
        return gen_free_enter(ctx, address);
}

int posix_memalign_enter(struct pt_regs *ctx, void **memptr, size_t alignment,
                         size_t size) {
        u64 memptr64 = (u64)(size_t)memptr;
        u32 tid = bpf_get_current_pid_tgid();

        memptrs.update(&tid, &memptr64);
        return gen_alloc_enter(ctx, size, POSIX_MEMALIGN);
}

int posix_memalign_exit(struct pt_regs *ctx) {
        u32 tid = bpf_get_current_pid_tgid();
        u64 *memptr64 = memptrs.lookup(&tid);
        void *addr;

        if (memptr64 == 0)
                return 0;

        memptrs.delete(&tid);

        if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
                return 0;

        u64 addr64 = (u64)(size_t)addr;
        return gen_alloc_exit2(ctx, addr64, POSIX_MEMALIGN);
}

int aligned_alloc_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size, ALIGNED_ALLOC);
}

int aligned_alloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx, ALIGNED_ALLOC);
}

int valloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size, VALLOC);
}

int valloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx, VALLOC);
}

int memalign_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size, MEMALIGN);
}

int memalign_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx, MEMALIGN);
}

int pvalloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size, PVALLOC);
}

int pvalloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx, PVALLOC);
}
"""

bpf_source_kernel_node = """

TRACEPOINT_PROBE(kmem, kmalloc_node) {
        if (WORKAROUND_MISSING_FREE)
            gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc, KERNEL);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr, KERNEL);
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc_node) {
        if (WORKAROUND_MISSING_FREE)
            gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc, KERNEL);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr, KERNEL);
}
"""

bpf_source_kernel = """

TRACEPOINT_PROBE(kmem, kmalloc) {
        if (WORKAROUND_MISSING_FREE)
            gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc, KERNEL);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr, KERNEL);
}

TRACEPOINT_PROBE(kmem, kfree) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc) {
        if (WORKAROUND_MISSING_FREE)
            gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc, KERNEL);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr, KERNEL);
}

TRACEPOINT_PROBE(kmem, kmem_cache_free) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

TRACEPOINT_PROBE(kmem, mm_page_alloc) {
        gen_alloc_enter((struct pt_regs *)args, PAGE_SIZE << args->order, KERNEL);
        return gen_alloc_exit2((struct pt_regs *)args, args->pfn, KERNEL);
}

TRACEPOINT_PROBE(kmem, mm_page_free) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->pfn);
}
"""

bpf_source_percpu = """

TRACEPOINT_PROBE(percpu, percpu_alloc_percpu) {
        gen_alloc_enter((struct pt_regs *)args, args->size, KERNEL);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr, KERNEL);
}

TRACEPOINT_PROBE(percpu, percpu_free_percpu) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}
"""

if kernel_trace:
        if args.percpu:
                bpf_source += bpf_source_percpu
        else:
                bpf_source += bpf_source_kernel
                if BPF.tracepoint_exists("kmem", "kmalloc_node"):
                        bpf_source += bpf_source_kernel_node

if kernel_trace:
    bpf_source = bpf_source.replace("WORKAROUND_MISSING_FREE", "1"
                                    if args.wa_missing_free else "0")

bpf_source = bpf_source.replace("SHOULD_PRINT", "1" if trace_all else "0")
bpf_source = bpf_source.replace("SAMPLE_EVERY_N", str(sample_every_n))
bpf_source = bpf_source.replace("PAGE_SIZE", str(resource.getpagesize()))

size_filter = ""
if min_size is not None and max_size is not None:
        size_filter = "if (size < %d || size > %d) return 0;" % \
                      (min_size, max_size)
elif min_size is not None:
        size_filter = "if (size < %d) return 0;" % min_size
elif max_size is not None:
        size_filter = "if (size > %d) return 0;" % max_size
bpf_source = bpf_source.replace("SIZE_FILTER", size_filter)

stack_flags = "0"
if not kernel_trace:
        stack_flags += "|BPF_F_USER_STACK"
bpf_source = bpf_source.replace("STACK_FLAGS", stack_flags)

if args.ebpf:
    print(bpf_source)
    exit()

bpf = BPF(text=bpf_source)

if not kernel_trace:
        print("Attaching to pid %d, Ctrl+C to quit." % pid)

        def attach_probes(sym, fn_prefix=None, can_fail=False, need_uretprobe=True):
                if fn_prefix is None:
                        fn_prefix = sym
                if args.symbols_prefix is not None:
                        sym = args.symbols_prefix + sym
                try:
                        bpf.attach_uprobe(name=obj, sym=sym,
                                          fn_name=fn_prefix + "_enter",
                                          pid=pid)
                        if need_uretprobe:
                                bpf.attach_uretprobe(name=obj, sym=sym,
                                             fn_name=fn_prefix + "_exit",
                                             pid=pid)
                except Exception:
                        if can_fail:
                                return
                        else:
                                raise

        attach_probes("malloc")
        attach_probes("calloc")
        attach_probes("realloc")
        attach_probes("mmap", can_fail=True) # failed on jemalloc
        attach_probes("posix_memalign")
        attach_probes("valloc", can_fail=True) # failed on Android, is deprecated in libc.so from bionic directory
        attach_probes("memalign")
        attach_probes("pvalloc", can_fail=True) # failed on Android, is deprecated in libc.so from bionic directory
        attach_probes("aligned_alloc", can_fail=True)  # added in C11
        attach_probes("free", need_uretprobe=False)
        attach_probes("munmap", can_fail=True, need_uretprobe=False) # failed on jemalloc

else:
        print("Attaching to kernel allocators, Ctrl+C to quit.")

        # No probe attaching here. Allocations are counted by attaching to
        # tracepoints.
        #
        # Memory allocations in Linux kernel are not limited to malloc/free
        # equivalents. It's also common to allocate a memory page or multiple
        # pages. Page allocator have two interfaces, one working with page
        # frame numbers (PFN), while other working with page addresses. It's
        # possible to allocate pages with one kind of functions, and free them
        # with another. Code in kernel can easy convert PFNs to addresses and
        # back, but it's hard to do the same in eBPF kprobe without fragile
        # hacks.
        #
        # Fortunately, Linux exposes tracepoints for memory allocations, which
        # can be instrumented by eBPF programs. Tracepoint for page allocations
        # gives access to PFNs for both allocator interfaces. So there is no
        # need to guess which allocation corresponds to which free.

def print_outstanding():
        print("[%s] Top %d stacks with outstanding allocations:" %
              (datetime.now().strftime("%H:%M:%S"), top_stacks))
        alloc_info = {}
        allocs = bpf["allocs"]
        stack_traces = bpf["stack_traces"]
        for address, info in sorted(allocs.items(), key=lambda a: a[1].size):
                if BPF.monotonic_time() - min_age_ns < info.timestamp_ns:
                        continue
                if info.stack_id < 0:
                        continue
                if info.stack_id in alloc_info:
                        alloc_info[info.stack_id].update(info.size)
                else:
                        stack = list(stack_traces.walk(info.stack_id))
                        combined = []
                        for addr in stack:
                                combined.append(('0x'+format(addr, '016x')+'\t').encode('utf-8') + bpf.sym(addr, pid,
                                        show_module=True, show_offset=True))
                        alloc_info[info.stack_id] = Allocation(combined,
                                                               info.size,
                                                               info.type_index)
                if args.show_allocs:
                        print("\taddr = %x size = %s" %
                              (address.value, info.size))
        to_show = sorted(alloc_info.values(), key=alloc_sort_map[sort_key])[-top_stacks:]
        for alloc in to_show:
                print("\t%d bytes in %d allocations of type %d from stack\n\t\t%s" %
                      (alloc.size, alloc.count, alloc.type_index,
                       b"\n\t\t".join(alloc.stack).decode("ascii")))

def print_outstanding_combined():
        stack_traces = bpf["stack_traces"]
        stacks = sorted(bpf["combined_allocs"].items(),
                        key=combined_sort_map[sort_key])
        cnt = 1
        entries = []
        for stack_id, info in stacks:
                try:
                        trace = []
                        for addr in stack_traces.walk(stack_id.value):
                                sym = bpf.sym(addr, pid,
                                                      show_module=True,
                                                      show_offset=True)
                                trace.append(sym.decode('utf-8'))
                        trace = "\n\t\t".join(trace)
                except KeyError:
                        trace = "stack information lost"

                entry = ("\t%d bytes in %d allocations from stack\n\t\t%s" %
                         (info.total_size, info.number_of_allocs, trace))
                entries.append(entry)

                cnt += 1
                if cnt > top_stacks:
                        break

        print("[%s] Top %d stacks with outstanding allocations:" %
              (datetime.now().strftime("%H:%M:%S"), top_stacks))

        print('\n'.join(reversed(entries)))

count_so_far = 0
while True:
        if trace_all:
                print(bpf.trace_fields())
        else:
                try:
                        sleep(interval)
                except KeyboardInterrupt:
                        exit()
                if args.combined_only:
                        print_outstanding_combined()
                else:
                        print_outstanding()
                sys.stdout.flush()
                count_so_far += 1
                if num_prints is not None and count_so_far >= num_prints:
                        exit()
