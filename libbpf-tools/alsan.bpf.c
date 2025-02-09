/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright 2022 LG Electronics Inc. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "alsan.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_THREAD_NUM);
	__type(key, u32);
	__type(value, u64);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_THREAD_NUM);
	__type(key, u32);
	__type(value, u64);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct alsan_info_t);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
} stack_traces SEC(".maps");

static int gen_alloc_enter(struct pt_regs *ctx, size_t size)
{
	u64 size64 = size;
	u32 tid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&sizes, &tid, &size64, BPF_ANY);

	return 0;
}

static int gen_alloc_exit(struct pt_regs *ctx, u64 address)
{
	struct alsan_info_t info = {};
	u32 tid = bpf_get_current_pid_tgid();
	u64 *size64 = bpf_map_lookup_elem(&sizes, &tid);

	if (!size64)
		return 0;

	info.size = *size64;
	bpf_map_delete_elem(&sizes, &tid);

	if (!address)
		return 0;

	info.stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
	info.tag = DIRECTLY_LEAKED;
	bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);

	return 0;
}

static int gen_free_enter(struct pt_regs *ctx, void *address)
{
	u64 addr = (u64)address;

	bpf_map_delete_elem(&allocs, &addr);

	return 0;
}

SEC("uprobe")
int BPF_KPROBE(malloc_entry, size_t size)
{
	return gen_alloc_enter(ctx, size);
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

SEC("uprobe")
int BPF_KPROBE(calloc_entry, size_t nmemb, size_t size)
{
	return gen_alloc_enter(ctx, nmemb * size);
}

SEC("uretprobe")
int BPF_KRETPROBE(calloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_KPROBE(realloc_entry, void *ptr, size_t size)
{
	gen_free_enter(ctx, ptr);

	return gen_alloc_enter(ctx, size);
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
	u32 tid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&memptrs, &tid, &memptr64, BPF_ANY);

	return gen_alloc_enter(ctx, size);
}

SEC("uretprobe")
int BPF_KRETPROBE(posix_memalign_return)
{
	void *addr = NULL;
	u64 addr64 = 0;
	u32 tid = bpf_get_current_pid_tgid();
	u64 *memptr64 = bpf_map_lookup_elem(&memptrs, &tid);

	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &tid);
	if (bpf_probe_read_user(&addr, sizeof(void *), (void *)(size_t)*memptr64))
		return 0;

	addr64 = (u64)(size_t)addr;

	return gen_alloc_exit(ctx, addr64);
}

SEC("uprobe")
int BPF_KPROBE(aligned_alloc_entry, size_t alignment, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("uretprobe")
int BPF_KRETPROBE(aligned_alloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_KPROBE(valloc_entry, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("uretprobe")
int BPF_KRETPROBE(valloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_KPROBE(memalign_entry, size_t alignment, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("uretprobe")
int BPF_KRETPROBE(memalign_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_KPROBE(pvalloc_entry, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("uretprobe")
int BPF_KRETPROBE(pvalloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_KPROBE(reallocarray_entry, void *ptr, size_t nmemb, size_t size)
{
	gen_free_enter(ctx, ptr);

	return gen_alloc_enter(ctx, nmemb * size);
}

SEC("uretprobe")
int BPF_KRETPROBE(reallocarray_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

char _license[] SEC("license") = "Dual BSD/GPL";
