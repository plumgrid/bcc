#!/usr/bin/env python3
#
# vqkick.py
#
# Trace virtqueue kick event for virtio driver.
# $./vqkick.py
# TIME               CPU  VQ_NAME
# 327344.930087496   5    b'output.0'
# 327344.930896929   5    b'output.0'
# 327344.930993290   5    b'output.0'
# 327344.931079160   5    b'output.0'
# 327344.931161010   5    b'output.0'
# 327344.931231561   5    b'output.0'

# @TIME: Timestamp for virtqueue kick event.
# @CPU: Which cpu occur virtqueue kick event.
# @VQ_NAME: Name of virtqueue.
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
#include <linux/virtio.h>

typedef struct event_log {
	u64 ts;
	u32 cpu;
	char vq_name[32];
} event_log_t;


BPF_PERF_OUTPUT(vq_kick_event);

int kprobe__virtqueue_notify(struct pt_regs *ctx, struct virtqueue *vq)
{
	event_log_t vq_kick_event_log = {};

	vq_kick_event_log.cpu = bpf_get_smp_processor_id();
	vq_kick_event_log.ts = bpf_ktime_get_ns();
	char *name = (char *)vq->name;
	bpf_probe_read_kernel(&vq_kick_event_log.vq_name, sizeof(vq_kick_event_log.vq_name), name);

	vq_kick_event.perf_submit(ctx, &vq_kick_event_log, sizeof(vq_kick_event_log));

	return 0;
}
'''

def print_vq_kick_event_log(cpu, data, size):
	event = b["vq_kick_event"].event(data)
	time_s = float(event.ts) / 1000000000
	print("%-18.9f %-4d %-16s" % (time_s, event.cpu, event.vq_name))


if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["vq_kick_event"].open_perf_buffer(print_vq_kick_event_log)

    # header
    print("\n%-18s %-4s %-32s" % ("TIME", "CPU", "VQ_NAME"))

    try:
        while True:
	        b.kprobe_poll(1)
    except KeyboardInterrupt:
        pass
