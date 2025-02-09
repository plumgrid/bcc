// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2022 Tencent.
// Author: Curu Wong

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "schedtimes.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

#define TASK_RUNNING            0x00000000
#define TASK_INTERRUPTIBLE      0x00000001
#define TASK_UNINTERRUPTIBLE    0x00000002
#define TASK_NOLOAD             0x00000400
#define EXIT_DEAD               0x00000010
#define EXIT_ZOMBIE             0x00000020

const volatile pid_t target_pid = 0;
const volatile pid_t target_tgid = 0;
const volatile pid_t target_ppid = 0;
const volatile bool no_sleeptime = false;

/* key: pid.  value: start time and state */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct state_ts_t);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct sched_times_t);
}  sched_times SEC(".maps");


static int update_times(struct task_struct *p, u64 delta, u32 state)
{
    struct sched_times_t *valuep;
    static const struct sched_times_t zero;
    u32 pid = BPF_CORE_READ(p, pid);
    if(!delta)
        return 0;
    valuep = bpf_map_lookup_or_try_init(&sched_times, &pid, &zero);
    if(!valuep){
        return 0;
    }
    bpf_probe_read_kernel_str(valuep->comm, sizeof(valuep->comm), p->comm);
    switch(state){
        case STATE_SLEEPING:
            valuep->sleep_time += delta;
            break;
        case STATE_BLOCKED:
            valuep->block_time += delta;
            break;
        case STATE_QUEUED:
            valuep->queue_time += delta;
            break;
        case STATE_RUNNING:
            valuep->run_time += delta;
            break;
        default:
            return 0;
    }
    return 0;
    
}

static bool allow_record(struct task_struct *p){
    u32 pid, tgid, ppid;
    pid = BPF_CORE_READ(p, pid);
    tgid = BPF_CORE_READ(p, tgid);
    ppid = BPF_CORE_READ(p, real_parent, tgid);
    if( pid == 0 )
        return false;
    if (target_pid && pid != target_pid)
        return false;
    else if(target_tgid && tgid != target_tgid)
        return false;
    else if (target_ppid && ppid != target_ppid)
        return false;
    return true;
}

static int handle_switch(struct task_struct *prev, struct task_struct *next)
{
    u32 prev_pid;
    u32 next_pid;
    u64 delta;
    u32 state = get_task_state(prev);
    struct state_ts_t state_ts, *state_tsp;

    __builtin_memset(&state_ts, 0, sizeof(state_ts));
    state_ts.ts = bpf_ktime_get_ns();
    
    //prev_pid sched out
    prev_pid = BPF_CORE_READ(prev, pid);
    if(allow_record(prev)){
        //caculate prev run_time
        state_tsp = bpf_map_lookup_elem(&start, &prev_pid); 
        if(state_tsp){
            delta = state_ts.ts - state_tsp->ts;
            update_times(prev, delta, STATE_RUNNING); 
        }

        //update start time
        if(state == TASK_RUNNING){
            state_ts.state = STATE_QUEUED;
        }else if(state & TASK_INTERRUPTIBLE){
            state_ts.state = STATE_SLEEPING;
        }else if((state & TASK_UNINTERRUPTIBLE) && !(state & TASK_NOLOAD)){
            state_ts.state = STATE_BLOCKED;
        }

        if(state & EXIT_ZOMBIE || state & EXIT_DEAD){
            //prev_pid exited
            bpf_map_delete_elem(&start, &prev_pid);
        }else{
            if(state_tsp){
                state_tsp->ts = state_ts.ts;
                state_tsp->state = state_ts.state;
            }else{
                bpf_map_update_elem(&start, &prev_pid, &state_ts, 0);
            }
        }

    }
    //next_pid sched in
    next_pid = BPF_CORE_READ(next, pid);
    if(allow_record(next)){
        //calculate queue time
        state_tsp = bpf_map_lookup_elem(&start, &next_pid);
        if(state_tsp && state_tsp->state == STATE_QUEUED){
            delta = state_ts.ts - state_tsp->ts;
            update_times(next, delta, STATE_QUEUED);
        }

        //update start time
        state_ts.state = STATE_RUNNING;
        if(state_tsp){
            state_tsp->ts = state_ts.ts;
            state_tsp->state = state_ts.state;
        }else{
            bpf_map_update_elem(&start, &next_pid, &state_ts, 0);
        }
    }
    return 0;
}

static int wakeup(struct task_struct *p)
{
    u32 pid; 
    u64 delta;
    struct state_ts_t state_ts, *state_tsp;
    __builtin_memset(&state_ts, 0, sizeof(state_ts));
    state_ts.ts = bpf_ktime_get_ns();

    pid = BPF_CORE_READ(p, pid);
    if(!allow_record(p))
        return 0;
    //caculate sleep/block time
    state_tsp = bpf_map_lookup_elem(&start, &pid);
    if(state_tsp){
        delta = state_ts.ts - state_tsp->ts;
        if(state_tsp->state == STATE_SLEEPING && !no_sleeptime)
            update_times(p, delta, STATE_SLEEPING);
        if(state_tsp->state == STATE_BLOCKED)
            update_times(p, delta, STATE_BLOCKED);
    }
    //update queue time
    state_ts.state = STATE_QUEUED;
    if(state_tsp){
        state_tsp->ts = state_ts.ts;
        state_tsp->state = state_ts.state;
    }else{
        bpf_map_update_elem(&start, &pid, &state_ts, BPF_ANY);
    }

    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    return handle_switch(prev, next);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    return wakeup(p);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
    return wakeup(p);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    return handle_switch(prev, next);
}
SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
    return wakeup(p);
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
    return wakeup(p);
}

char LICENSE[] SEC("license") = "GPL";
