// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Ze Gao

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "offwaketime.h"

#define PF_KTHREAD 0x00200000 /* I am a kernel thread */
#define MAX_ENTRIES 10240

const volatile bool kernel_threads_only = false;
const volatile bool user_threads_only = false;
const volatile __u64 max_block_ns = -1;
const volatile __u64 min_block_ns = 1;
const volatile pid_t targ_tgid = -1;
const volatile pid_t targ_pid = -1;
const volatile long state = -1;

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, u32);
        __type(value, u64);
        __uint(max_entries, MAX_ENTRIES);
} start SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_STACK_TRACE);
        __uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, u32);
        __type(value, struct pkey_t);
        __uint(max_entries, MAX_ENTRIES);
} wokeby SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, struct count_key_t);
        __type(value, u64);
        __uint(max_entries, MAX_ENTRIES);
} count SEC(".maps");

static inline bool allow_record(u32 pid, u32 tgid, u32 flags, long pstate) {
        if (targ_tgid != -1 && targ_tgid != tgid)
                return false;
        if (targ_pid != -1 && targ_pid != pid)
                return false;
        if (user_threads_only && flags & PF_KTHREAD)
                return false;
        else if (kernel_threads_only && !(flags & PF_KTHREAD))
                return false;
        if (state != -1 && pstate != state)
                return false;
        return true;
}

struct task_struct___new {
        long __state;
} __attribute__((preserve_access_index));

SEC("kprobe/try_to_wake_up")
int BPF_KPROBE(try_to_wake_up, struct task_struct *p) {
        u32 pid, tgid, flags, pstate;
        struct pkey_t woke;
        struct task_struct___new *p_new;

        pid = BPF_CORE_READ(p, pid);
        tgid = BPF_CORE_READ(p, tgid);
        flags = BPF_CORE_READ(p, flags);
        p_new = (void *)p;
        if (bpf_core_field_exists(p_new->__state)) {
                pstate = BPF_CORE_READ(p_new, __state);
        } else {
                pstate = BPF_CORE_READ(p, state);
        }
        if (allow_record(pid, tgid, flags, pstate)) {
                woke.pid = bpf_get_current_pid_tgid();
                woke.tgid = bpf_get_current_pid_tgid() >> 32;
                woke.kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
                if (flags & PF_KTHREAD)
                        woke.user_stack_id = -1;
                else
                        woke.user_stack_id =
                            bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
                bpf_get_current_comm(&woke.comm, sizeof(woke.comm));
                bpf_map_update_elem(&wokeby, &pid, &woke, BPF_ANY);
        }
        return 0;
}

SEC("kprobe/finish_task_switch")
int BPF_KPROBE(on_cpu, struct task_struct *prev) {
        u64 zero = 0, *val;
        u64 delta, ts, *tsp;
        u32 pid, tgid, flags, pstate;
	struct task_struct___new* prev_new;
        struct count_key_t key;
	struct pkey_t *woke;

        pid = BPF_CORE_READ(prev, pid);
        tgid = BPF_CORE_READ(prev, tgid);
        tgid = BPF_CORE_READ(prev, tgid);
        flags = BPF_CORE_READ(prev, flags);
        prev_new = (void *)prev;
        if (bpf_core_field_exists(prev_new->__state)) {
                pstate = BPF_CORE_READ(prev_new, __state);
        } else {
                pstate = BPF_CORE_READ(prev, state);
        }
        if (allow_record(pid, tgid, flags, pstate)) {
                /* record previous thread sleep time */
                ts = bpf_ktime_get_ns();
                bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
        }

        /* calculate current thread's delta time */
        pid = bpf_get_current_pid_tgid();
        tgid = bpf_get_current_pid_tgid() >> 32;
        tsp = bpf_map_lookup_elem(&start, &pid);
        if (!tsp)
                return 0;
        delta = bpf_ktime_get_ns() - *tsp;
        bpf_map_delete_elem(&start, &pid);
        delta = delta / 1000;
        if (delta < min_block_ns || delta > max_block_ns)
                return 0;

        key.target.pid = pid;
        key.target.tgid = tgid;
        key.target.kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
        if (flags & PF_KTHREAD)
                key.target.user_stack_id = -1;
        else
                key.target.user_stack_id =
                    bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
        bpf_get_current_comm(&key.target.comm, sizeof(key.target.comm));
        __builtin_memset(&key.waker, 0, sizeof(key.waker));
        woke = bpf_map_lookup_elem(&wokeby, &pid);
        if (woke) {
                key.waker.pid = woke->pid;
                key.waker.tgid = woke->tgid;
                key.waker.kern_stack_id = woke->kern_stack_id;
                key.waker.user_stack_id = woke->user_stack_id;
                __builtin_memcpy(&key.waker.comm, woke->comm,
                                 sizeof(key.waker.comm));
                bpf_map_delete_elem(&wokeby, &pid);
        }

        val = bpf_map_lookup_elem(&count, &key);
        if (!val) {
                bpf_map_update_elem(&count, &key, &zero, BPF_NOEXIST);
                val = bpf_map_lookup_elem(&count, &key);
                if (!val)
                        return 0;
        }
        __sync_fetch_and_add(val, delta);
        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
