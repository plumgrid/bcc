// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Tiago Ilieve
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "pidpersec.h"

__u64 stats[S_MAXSTAT] = {};

SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(void *ctx)
{
	__atomic_add_fetch(&stats[S_COUNT], 1, __ATOMIC_RELAXED);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
