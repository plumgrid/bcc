/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright 2022 LG Electronics Inc. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "doublefree.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, u32);
	__type(value, u32);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct doublefree_info_t);
	__uint(max_entries, MAX_ENTRIES);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u32);
	__uint(max_entries, MAX_ENTRIES);
} deallocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
	__uint(max_entries, MAX_ENTRIES);
} stack_traces SEC(".maps");

static int gen_alloc_exit(struct pt_regs *ctx, u64 address)
{
	struct doublefree_info_t info = {};

	if (!address)
		return 0;

	info.stackid = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
	info.alloc_count = 1;
	bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);

	return 0;
}

static int gen_free_enter(struct pt_regs *ctx, void *address)
{
	int stackid = 0;
	u64 addr = (u64)address;
	struct event event = {};
	struct doublefree_info_t *info = bpf_map_lookup_elem(&allocs, &addr);

	if (!info)
		return 0;

	stackid = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

	__sync_fetch_and_add(&info->alloc_count, -1);
	if (info->alloc_count == 0) {
		bpf_map_update_elem(&deallocs, &addr, &stackid, BPF_ANY);
	} else if (info->alloc_count < 0) {
		event.stackid = stackid;
		event.addr = addr;
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
				      sizeof(event));
	} else {
		event.err = -1;
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
				      sizeof(event));
	}

	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_KPROBE(free_entry, void *address)
{
	return gen_free_enter(ctx, address);
}

SEC("uretprobe")
int BPF_KRETPROBE(calloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_KPROBE(realloc_entry, void *ptr, size_t size)
{
	return gen_free_enter(ctx, ptr);
}

SEC("uretprobe")
int BPF_KRETPROBE(realloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_KPROBE(posix_memalign_entry, void **memptr, size_t alignment, size_t size)
{
	u64 memptr64 = (u64)(size_t)memptr;
	u64 pid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);

	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(posix_memalign_return)
{
	void *addr = NULL;
	u64 addr64 = 0;
	u64 pid = bpf_get_current_pid_tgid();
	u64 *memptr64 = bpf_map_lookup_elem(&memptrs, &pid);

	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &pid);

	if (bpf_probe_read_user(&addr, sizeof(void *), (void *)(size_t)*memptr64))
		return 0;

	addr64 = (u64)(size_t)addr;

	return gen_alloc_exit(ctx, addr64);
}

SEC("uretprobe")
int BPF_KRETPROBE(aligned_alloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe")
int BPF_KRETPROBE(valloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe")
int BPF_KRETPROBE(memalign_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe")
int BPF_KRETPROBE(pvalloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_KPROBE(reallocarray_entry, void *ptr, size_t nmemb, size_t size)
{
	return gen_free_enter(ctx, ptr);
}

SEC("uretprobe")
int BPF_KRETPROBE(reallocarray_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

char _license[] SEC("license") = "Dual BSD/GPL";
