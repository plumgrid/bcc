// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "compat.bpf.h"
#include "execsnoop.h"

const volatile bool filter_cg = false;
const volatile bool ignore_failed = true;
const volatile uid_t targ_uid = INVALID_UID;
const volatile int max_args = DEFAULT_MAXARGS;

static const struct event empty_event = {};

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct event);
} execs SEC(".maps");

static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct syscall_trace_enter* ctx)
{
	u64 id;
	pid_t pid, tgid;
	int ret;
	struct event *event;
	struct task_struct *task;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	uid_t uid = (u32)bpf_get_current_uid_gid();
	int i;

	if (valid_uid(targ_uid) && targ_uid != uid)
		return 0;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;
	if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
		return 0;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->pid = tgid;
	event->uid = uid;
	task = (struct task_struct*)bpf_get_current_task();
	event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
	event->args_count = 0;
	event->args_size = 0;

	ret = bpf_probe_read_user_str(event->args, ARGSIZE, (const char*)ctx->args[0]);
	if (ret < 0) {
		return 0;
	}
	if (ret <= ARGSIZE) {
		event->args_size += ret;
	} else {
		/* write an empty string */
		event->args[0] = '\0';
		event->args_size++;
	}

	event->args_count++;
	#pragma unroll
	for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
		ret = bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
		if (ret < 0)
			return 0;

		if (event->args_size > LAST_ARG)
			return 0;

		ret = bpf_probe_read_user_str(&event->args[event->args_size], ARGSIZE, argp);
		if (ret < 0)
			return 0;

		event->args_count++;
		event->args_size += ret;
	}
	/* try to read one more argument to check if there is one */
	ret = bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
	if (ret < 0)
		return 0;

	/* pointer to max_args+1 isn't null, asume we have more arguments */
	event->args_count++;
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct syscall_trace_exit* ctx)
{
	u64 id;
	pid_t pid;
	int ret;
	struct event *event;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	u32 uid = (u32)bpf_get_current_uid_gid();

	if (valid_uid(targ_uid) && targ_uid != uid)
		return 0;
	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;
	ret = ctx->ret;
	if (ignore_failed && ret < 0)
		goto cleanup;

	event->retval = ret;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	size_t len = EVENT_SIZE(event);
	if (len <= sizeof(*event))
		submit_buf(ctx, event, sizeof(*event));
cleanup:
	bpf_map_delete_elem(&execs, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
