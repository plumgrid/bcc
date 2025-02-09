// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Copyright (c) 2022 LG Electronics
 *
 * Based on profile from BCC by Brendan Gregg and others.
 * 28-Dec-2021   Eunseon Lee   Created this.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "profile.h"
#include "maps.bpf.h"

const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile bool include_idle = false;
const volatile bool filter_by_pid = false;
const volatile bool filter_by_tid = false;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmapback SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} countsback SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_PID_NR);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_TID_NR);
} tids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, bool);
	__uint(max_entries, 1);
} changes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} countsusers SEC(".maps");


SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = id;
	u64 *valp;
	static const u64 zero;
	struct key_t key = {};

	if (!include_idle && tid == 0)
		return 0;

	if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid))
		return 0;

	if (filter_by_tid && !bpf_map_lookup_elem(&tids, &tid))
		return 0;

	u32 change_key = 0;
	bool *change_value;
	change_value = bpf_map_lookup_elem(&changes, &change_key);
	if (change_value == 0) {
		return 0;
	}

	key.pid = pid;
	bpf_get_current_comm(&key.name, sizeof(key.name));

	if (user_stacks_only) {
		key.kern_stack_id = -1;
	}
	else {
		if (*change_value == true) {
			key.kern_stack_id = bpf_get_stackid(&ctx->regs, &stackmap, 0);
		} else {
			key.kern_stack_id = bpf_get_stackid(&ctx->regs, &stackmapback, 0);
		} 
	}

	if (kernel_stacks_only) {
		key.user_stack_id = -1;
	}
	else {
		if (*change_value == true) {
			key.user_stack_id = bpf_get_stackid(&ctx->regs, &stackmap,
						    BPF_F_USER_STACK);
		} else {
			key.user_stack_id = bpf_get_stackid(&ctx->regs, &stackmapback,
						    BPF_F_USER_STACK);
		} 
	}

	if (*change_value == true) {
		valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
		if (valp)
			__sync_fetch_and_add(valp, 1);
	} else {
		valp = bpf_map_lookup_or_try_init(&countsback, &key, &zero);
		if (valp)
			__sync_fetch_and_add(valp, 1);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
