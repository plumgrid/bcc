// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Tiago Ilieve
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"
#include "vfscount.h"

#define MAX_ENTRIES	256

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct key_t);
} counts SEC(".maps");

SEC("kprobe/dummy_kprobe")
int dummy_kprobe(struct pt_regs *ctx)
{
	struct key_t key = {};
	u64 zero = 0;
	u64 *val;

	key.ip = PT_REGS_IP(ctx);

	val = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (val != NULL) {
		__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
