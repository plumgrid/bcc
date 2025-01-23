// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Samsung */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "blkalgn.h"
#include "bits.bpf.h"
#include "core_fixes.bpf.h"

const volatile bool filter_dev = false;
const volatile __u32 targ_dev = 0;
const volatile bool filter_ops = false;
const volatile __u32 targ_ops = 0;

extern __u32 LINUX_KERNEL_VERSION __kconfig;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2097152);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct hkey);
	__type(value, struct hval);
} halgn_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct hkey);
	__type(value, struct hval);
} hgran_map SEC(".maps");

static int __always_inline trace_rq_issue(struct request *rq)
{
	struct event *e;
	u32 dev;

	struct gendisk *disk = get_disk(rq);

	dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
			   BPF_CORE_READ(disk, first_minor)) :
		     0;

	if (filter_dev && targ_dev != dev)
		return 0;

	if (filter_ops && targ_ops != (rq->cmd_flags & 0xff))
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_kernel(&e->disk, sizeof(e->disk),
			      rq->q->disk->disk_name);

	e->flags = rq->cmd_flags;
	e->lbs = rq->q->limits.logical_block_size;
	e->len = rq->__data_len;
	e->sector = rq->__sector;

	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue)
{
	/*
	 * Commit a54895fa (v5.11-rc1) changed tracepoint argument list
	 * from TP_PROTO(struct request_queue *q, struct request *rq)
	 * to TP_PROTO(struct request *rq)
	 */
	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 11, 0))
		return trace_rq_issue((void *)ctx[0]);
	else
		return trace_rq_issue((void *)ctx[1]);
}
