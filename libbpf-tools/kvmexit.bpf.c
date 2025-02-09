/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "kvmexit.h"
#include "maps.bpf.h"

#define MAX_TIDS	1024
#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;
const volatile pid_t target_tid = 0;
const volatile bool trace_by_process = true;
const volatile bool filter_by_tid = false;
static struct exit_stat zero_value = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TIDS);
	__type(key, pid_t);
	__type(value, pid_t);
} tids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct exit_key);
	__type(value, struct exit_stat);
} entries SEC(".maps");

SEC("tp_btf/kvm_exit")
int BPF_PROG(kvm_exit_btf, int exit_reason)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct exit_key key;
	struct exit_stat *valuep;

	if (target_pid && target_pid != pid)
		return 0;
	if (target_tid && target_tid != tid)
		return 0;
	if (filter_by_tid && !bpf_map_lookup_elem(&tids, &tid))
		return 0;
	if (trace_by_process)
		tid = 0;

	key.pid = pid;
	key.tid = tid;
	key.exit_reason = exit_reason;
	valuep = bpf_map_lookup_or_try_init(&entries, &key, &zero_value);
	if (!valuep) {
		return 0;
	}
	valuep->pid = pid;
	valuep->tid = tid;
	valuep->exit_reason = exit_reason;
	valuep->count++;
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
