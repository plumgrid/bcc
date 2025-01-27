// SPDX-License-Identifier: GPL-2.0
// Copyright 2024 Sony Group Corporation

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "filegone.h"
#include "core_fixes.bpf.h"

#define FMODE_CREATED	0x100000

const volatile pid_t targ_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32); /* tid */
	__type(value, struct event);
} currevent SEC(".maps");

/* In different kernel versions, function vfs_unlink() has three declarations,
 * and their parameter lists are as follows:
 *
 * int vfs_unlink(struct inode *dir, struct dentry *dentry,
 *        struct inode **delegated_inode);
 * int vfs_unlink(struct user_namespace *mnt_userns, struct inode *dir,
 *        struct dentry *dentry, struct inode **delegated_inode);
 * int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir,
 *        struct dentry *dentry, struct inode **delegated_inode);
 */
SEC("kprobe/vfs_unlink")
int BPF_KPROBE(vfs_unlink, void *arg0, void *arg1, void *arg2)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tid = (u32)id;
	struct event event = {};
	const u8 *qs_name_ptr;
	u32 tgid = id >> 32;

	if (targ_tgid && targ_tgid != tgid)
				return 0;

	bool has_arg = renamedata_has_old_mnt_userns_field()
				|| renamedata_has_new_mnt_idmap_field();
	qs_name_ptr = has_arg
		? BPF_CORE_READ((struct dentry *)arg2, d_name.name)
		: BPF_CORE_READ((struct dentry *)arg1, d_name.name);
	bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), qs_name_ptr);
	bpf_get_current_comm(&event.task, sizeof(event.task));
	event.action = 'D';
	event.tgid = tgid;

	bpf_map_update_elem(&currevent, &tid, &event, BPF_ANY);
	return 0;
}

/* vfs_rename() has two declarations in different kernel versions with the following parameter lists-
 * int vfs_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
	struct dentry *new_dentry, struct inode **delegated_inode, unsigned int flags);
 * int vfs_rename(struct renamedata *);
 */
SEC("kprobe/vfs_rename")
int BPF_KPROBE(vfs_rename, void *arg0, void *arg1, void *arg2, void *arg3)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tid = (u32)id;
	struct event event = {};
	struct qstr qs_name_ptr;
	struct qstr qd_name_ptr;
	u32 tgid = id >> 32;

	if (targ_tgid && targ_tgid != tgid)
		return 0;

	bool has_arg = renamedata_has_old_mnt_userns_field()
				|| renamedata_has_new_mnt_idmap_field();
	qs_name_ptr = has_arg
		? BPF_CORE_READ((struct renamedata *)arg0, old_dentry, d_name)
		: BPF_CORE_READ((struct dentry *)arg1, d_name);
	qd_name_ptr = has_arg
		? BPF_CORE_READ((struct renamedata *)arg0, new_dentry, d_name)
		: BPF_CORE_READ((struct dentry *)arg3, d_name);
	bpf_get_current_comm(&event.task, sizeof(event.task));
	bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), qs_name_ptr.name);
	bpf_probe_read_kernel_str(&event.fname2, sizeof(event.fname2), qd_name_ptr.name);
	event.action = 'R';
	event.tgid = tgid;

	bpf_map_update_elem(&currevent, &tid, &event, BPF_ANY);
	return 0;
}

static int handle_kretprobe(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tid = (u32)id;
	int ret = PT_REGS_RC(ctx);
	struct event *event;

	event = bpf_map_lookup_elem(&currevent, &tid);
	if (!event)
		return 0;

	bpf_map_delete_elem(&currevent, &tid);

	/* Skip failed unlink or rename */
	if (ret)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
	return 0;
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(vfs_unlink_ret)
{
	return handle_kretprobe(ctx);
}

SEC("kretprobe/vfs_rename")
int BPF_KRETPROBE(vfs_rename_ret)
{
	return handle_kretprobe(ctx);
}

char LICENSE[] SEC("license") = "GPL";
