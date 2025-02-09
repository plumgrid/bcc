#!/usr/bin/env python
#
# kernel_cache_alloc_free.py - Kernel memory (alloc-free) monitoring tool.
#
# Written as a basic tool example of using ePBF
# to track of kernel cache allocation and deallocation process.
#
# Copyright (c) 2019 Jugurtha BELKALEM.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Jan-2019 Jugurtha BELKALEM Created this.

from bcc import BPF
import ctypes as ct
# prog will store the eBPF C program
counter = 0;
prog = """
struct memory_allocations {
    u64 timestamp;
    u64 call_site;
    u64 ptr;
    u64 bytes_req;
    u64 bytes_alloc;
    u32 gfp_flags;
    char command[30];
};

BPF_PERF_OUTPUT(events_alloc);

BPF_PERF_OUTPUT(events_free);

TRACEPOINT_PROBE(kmem, kmem_cache_alloc)
{
    struct memory_allocations memoryAllocationsInstance = {};
    memoryAllocationsInstance.timestamp = bpf_ktime_get_ns();
    memoryAllocationsInstance.call_site = args->call_site;
    memoryAllocationsInstance.ptr = (u64)args->ptr;
    memoryAllocationsInstance.bytes_req = args->bytes_req;
    memoryAllocationsInstance.bytes_alloc = args->bytes_alloc;
    memoryAllocationsInstance.gfp_flags = args->gfp_flags;
    sprintf(memoryAllocationsInstance.command,"%s", "kmem_cache_alloc");
    events_alloc.perf_submit(args, &memoryAllocationsInstance, sizeof(memoryAllocationsInstance));
    return 0; 
}

TRACEPOINT_PROBE(kmem, kmem_cache_free)
{
    struct memory_allocations memoryFreeInstance = {};
    memoryFreeInstance.timestamp = bpf_ktime_get_ns();
    memoryFreeInstance.call_site = args->call_site;
    memoryFreeInstance.ptr = (u64)args->ptr;
    memoryFreeInstance.bytes_req = 0;
    memoryFreeInstance.bytes_alloc = 0;
    memoryFreeInstance.gfp_flags = 0;
    sprintf(memoryFreeInstance.command,"%s", "kmem_cache_free");
    events_free.perf_submit(args, &memoryFreeInstance, sizeof(memoryFreeInstance));
    return 0;
}
"""

# Loads eBPF program
b = BPF(text=prog)

class Data(ct.Structure):
    _fields_ = [("timestamp", ct.c_ulonglong), ("call_site", ct.c_ulonglong),("ptr", ct.c_ulonglong),("bytes_req", ct.c_ulonglong),("bytes_alloc", ct.c_ulonglong),("gfp_flags", ct.c_uint), ("command", ct.c_char * 30)]

# Show message when ePBF stats
print("Kernel cache allocation started ... Hit Ctrl-C to end!")

print("%-18s %-22s %-24s %-15s %-12s %-32s %-30s" % ("TIME(S)", "Call_site", "ptr", "bytes_req", "bytes_alloc", "gfp_flags", "Command"))

def display_kernel_alloc_free(cpu, data, size):
    evenement = ct.cast(data, ct.POINTER(Data)).contents
    print("%-18.0f %-22.0f 0x%-22.0f %-15.0f %-12.0f 0x%-30d %-29s" % (evenement.timestamp, evenement.call_site, evenement.ptr, evenement.bytes_req, evenement.bytes_alloc, evenement.gfp_flags, evenement.command))

b["events_alloc"].open_perf_buffer(display_kernel_alloc_free)
b["events_free"].open_perf_buffer(display_kernel_alloc_free)

while 1: 
	b.perf_buffer_poll()
