#!/usr/bin/env python3
#
# virtionet.py
#
# Display information about the data received from virtio_net driver.
# $./virtionet.py
# TIME               CPU  PID    BUF_LEN
# 255982.456288938   7    0      78
# 255982.457095461   7    0      78
# 255982.457242272   7    0      78
# 255982.457377682   7    0      78
# 255982.457510673   7    0      78
# 255982.457627593   7    0      78
#
# @TIME: Timestamp for received pkt.
# @CPU: which cpu receive this pkt.
# @PID: The process being executed on the CPU.
# @BUF_LEN: Length of received pkt.
#
# Copyright (c) 2023 kylinos Inc. All rights reserved.
#
# Author(s):
#   Longjun Tang <tanglongjun@kylinos.cn>


import sys
from bcc import BPF
import argparse


# define BPF program
bpf_text = '''
#include <uapi/linux/ptrace.h>

typedef struct event_log {
	u64 ts;
	u32 cpu;
	u32 pid;
	u32 buf_len;
} event_log_t;


BPF_PERF_OUTPUT(rcv_buf_event);

int kprobe__receive_buf(struct pt_regs *ctx, void *vi, void *rq, void *buf, unsigned int len)
{
	event_log_t rcv_buf_event_log = {};

	rcv_buf_event_log.cpu = bpf_get_smp_processor_id();
	rcv_buf_event_log.ts = bpf_ktime_get_ns();
	rcv_buf_event_log.buf_len = len;
	rcv_buf_event_log.pid = bpf_get_current_pid_tgid();

	rcv_buf_event.perf_submit(ctx, &rcv_buf_event_log, sizeof(rcv_buf_event_log));

	return 0;
}
'''

def print_rcv_buf_event_log(cpu, data, size):
	event = b["rcv_buf_event"].event(data)
	time_s = float(event.ts) / 1000000000
	print("%-18.9f %-4d %-6d %-6d" % (time_s, event.cpu, event.pid, event.buf_len))


if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["rcv_buf_event"].open_perf_buffer(print_rcv_buf_event_log)

    # header
    print("\n%-18s %-4s %-6s %-6s" % ("TIME", "CPU", "PID", "BUF_LEN"))

    try:
        while True:
	        b.kprobe_poll(1)
    except KeyboardInterrupt:
        pass
