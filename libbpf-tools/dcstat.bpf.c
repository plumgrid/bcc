// SPDX-License-Identifier: GPL-2.0
// Copyright 2024 Sony Group Corporation
//
// Based on dcstat(8) from BCC by Brendan Gregg

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "dcstat.h"

__u64 stats[S_MAXSTAT] = {};

static __always_inline int inc_stats(int key)
{
	__atomic_add_fetch(&stats[key], 1, __ATOMIC_RELAXED);
	return 0;
}

SEC("kprobe/lookup_fast")
int BPF_KPROBE(lookup_fast)
{
	return inc_stats(S_REFS);
}

SEC("kretprobe/d_lookup")
int BPF_KRETPROBE(d_lookup_ret)
{
	inc_stats(S_SLOW);
	if (PT_REGS_RC(ctx) == 0) {
		inc_stats(S_MISS);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
