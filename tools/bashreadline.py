#!/usr/bin/python
#
# bashreadline  Print entered bash commands from all running shells.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# This works by tracing the readline() function using a uretprobe (uprobes).
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 28-Jan-2016    Brendan Gregg   Created this.
# 12-Feb-2016    Allan McAleavy migrated to BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
from time import strftime

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
// include <linux/sched.h>

struct str_t {
    u64 pid;
 // If you use Arch Linux, you may need this field to filter info
 // char comm[TASK_COMM_LEN];
    char str[80];
};

BPF_PERF_OUTPUT(events);

int printret(struct pt_regs *ctx) {
    struct str_t data  = {};
    u32 pid;
    if (!PT_REGS_RC(ctx))
        return 0;
    pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    bpf_probe_read(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));
 // bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx,&data,sizeof(data));

    return 0;
};
"""

b = BPF(text=bpf_text)
# if you run this script on Arch Linux, change the value of name parameter
# to `/lib/libreadline.so` and get `comm` field of processes to filter info
b.attach_uretprobe(name="/bin/bash", sym="readline", fn_name="printret")

# header
print("%-9s %-6s %s" % ("TIME", "PID", "COMMAND"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-9s %-6d %s" % (strftime("%H:%M:%S"), event.pid,
                            event.str.decode('utf-8', 'replace')))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
