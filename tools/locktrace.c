#include <uapi/linux/futex.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/time.h>

#define PID_FILTER(pid) PID_FILTER_EXPR
#define SYS_TIME_SANITY_THRESHOLD 500

enum dbg_stat {
    HAS_DEBUG_STATS_ENUM_VALS
};

#if HAS_DEBUG_STATS
BPF_HASH(dbg_stats, u32, u32, 100);

static inline unsigned int encode_cmd_stat(enum dbg_stat s, int cmd) {
    return (s << 16) + cmd;
}
#endif

static inline void dbg_stat_inc(enum dbg_stat s) {
#if HAS_DEBUG_STATS
    dbg_stats.increment(s);
#endif
}

static inline void dbg_stat_inc_cmd(enum dbg_stat s, int cmd) {
#if HAS_DEBUG_STATS
    dbg_stats.increment(s);
    dbg_stats.increment(encode_cmd_stat(s, cmd));
#endif
}

struct cur_lock {
    u64 uaddr;
    u64 futex_enter_time;
    u64 block_time;
    u64 resume_time;
    u32 tgid;
    int usr_stack_id;
    int cpu;
    int cmd;
    bool invalid_sys_time;
};

struct lockaddr_key {
    u64 uaddr;
    int tgid;
};

struct hist_key {
    struct lockaddr_key key;
    u32 slot;
};


// pid -> current sys_futex lock
BPF_HASH(pid_lock, u32, struct cur_lock, 1000);
// lock_key -> lock_stats
// This is where the accumulated stats go
BPF_HASH(lock_stats, struct lock_key, struct lock_stats, 1000000);
// User and kernel stacks
BPF_STACK_TRACE(usr_stack_traces, STACK_STORAGE_SIZE);
BPF_STACK_TRACE(kernel_stack_traces, STACK_STORAGE_SIZE);
// Block time distributions
BPF_HISTOGRAM(dist, struct hist_key, 100000);
// Sampled cycles
BPF_HASH(cycle_counts, struct sample_key, uint64_t, 1000000);

static inline struct lock_stats *
lookup_lock_stats(u32 pid, u32 tgid, struct cur_lock *lock) {
    struct lock_stats zero = {};
    struct lock_key key = {.pid=pid, .tgid=tgid};
    key.uaddr = lock->uaddr;
    key.usr_stack_id = lock->usr_stack_id;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    return lock_stats.lookup_or_init(&key, &zero);
}

static inline void
stats_record_error(u32 pid, u32 tgid, struct cur_lock *lock) {
    struct lock_stats *stats = lookup_lock_stats(pid, tgid, lock);
    if (stats != 0) {
        stats->errors++;
    } else {
        dbg_stat_inc_cmd(FUTEX_ERROR_MISSING_RECORD, lock->cmd);
    }
}

// FUTEX_FD has been removed
// FUTEX_TRYLOCK_PI neither causes a wait nor a wake, but
// is included here for completeness
static bool is_wait(int cmd) {
    static const int wait_mask =
        (1 << FUTEX_WAIT) | (1 << FUTEX_LOCK_PI) |
        (1 << FUTEX_WAIT_BITSET) | (1 << FUTEX_WAIT_REQUEUE_PI) |
        (1 << FUTEX_TRYLOCK_PI);
    return (1 << cmd) & wait_mask;
}

static bool is_wake(int cmd) {
     // Requeue operations may not actually wake up any threads
     // (if the val arg is 0), but it's still OK to classify as wake
     // as the threads are moved along to another futex queue
     static const int wake_mask =
         (1 << FUTEX_WAKE) | (1 << FUTEX_WAKE_OP) |
         (1 << FUTEX_REQUEUE) | (1 << FUTEX_CMP_REQUEUE) |
         (1 << FUTEX_UNLOCK_PI) | (1 << FUTEX_WAKE_BITSET) |
         (1 << FUTEX_CMP_REQUEUE_PI);
     return (1 << cmd) & wake_mask;
}

static inline u32 nsec_to_usec(u64 t) {
    return (u32) (t / 1000);
}

static inline u32 usec_to_msec(u32 t) {
    return t / 1000;
}

static inline u32 nsec_to_msec(u64 t) {
    return usec_to_msec(nsec_to_usec(t));
}

#if HAS_DEBUG_STATS
// Various sanity checks and stats useful for tool debugging
static inline void update_debug_stats(
      struct cur_lock *lock, u32 elapsed_sys_us, u64 timestamp) {
    if (is_wait(lock->cmd)) {
        if (lock->block_time == 0 && lock->resume_time == 0) {
            if (is_wait(lock->cmd)) {
              dbg_stat_inc_cmd(FUTEX_WAIT_NOT_BLOCKED, lock->cmd);
            }
        } else if (lock->block_time == 0) {
            dbg_stat_inc_cmd(FUTEX_ERROR_MISSING_BLOCK_TIME, lock->cmd);
        } else if (lock->resume_time == 0) {
            dbg_stat_inc_cmd(FUTEX_ERROR_MISSING_RESUME, lock->cmd);
        } else if (lock->block_time > lock->resume_time) {
            dbg_stat_inc_cmd(FUTEX_ERROR_BLOCK_TIME_LATER_THAN_RESUME, lock->cmd);
        }
    } else if (lock->block_time != 0) {
        dbg_stat_inc(FUTEX_WAKE_BLOCKED);
    }

    if (!lock->invalid_sys_time && elapsed_sys_us > 300) {
        if (elapsed_sys_us > 5000)
          dbg_stat_inc(FUTEX_LONG_SYS_TIME_5ms);
        else if (elapsed_sys_us > 4000)
          dbg_stat_inc(FUTEX_LONG_SYS_TIME_4ms);
        else if (elapsed_sys_us > 3000)
          dbg_stat_inc(FUTEX_LONG_SYS_TIME_3ms);
        else if (elapsed_sys_us > 2000)
          dbg_stat_inc(FUTEX_LONG_SYS_TIME_2ms);
        else if (elapsed_sys_us > 1000)
          dbg_stat_inc(FUTEX_LONG_SYS_TIME_1ms);
        else if (elapsed_sys_us > 500)
          dbg_stat_inc(FUTEX_LONG_SYS_TIME_500us);
        else
          dbg_stat_inc(FUTEX_LONG_SYS_TIME_300us);
        dbg_stat_inc_cmd(FUTEX_LONG_SYS_TIME, lock->cmd);
        if (lock->block_time == 0) {
            dbg_stat_inc_cmd(FUTEX_LONG_SYS_TIME_NOT_BLOCKED, lock->cmd);
        } else if (lock->resume_time == 0) {
            dbg_stat_inc_cmd(FUTEX_LONG_SYS_TIME_MISSING_RESUME, lock->cmd);
        }
    }
    if (lock->block_time != 0 &&
            nsec_to_msec(lock->block_time - lock->futex_enter_time) > 1) {
        dbg_stat_inc_cmd(FUTEX_ENTER_DELAY, lock->cmd);
    }
    if (is_wait(lock->cmd) && lock->resume_time != 0 &&
            nsec_to_msec(timestamp - lock->resume_time) > 1) {
        dbg_stat_inc_cmd(FUTEX_EXIT_DELAY, lock->cmd);
    }
}
#endif

// This is called at the end of sys_futex_exit to record stats collected during
// the call to sys_futex for a particular thread
static inline void
update_stats(u32 pid, u32 tgid, u64 timestamp,
             struct cur_lock *lock) {
    u32 elapsed_blocked_us = 0;
    u32 elapsed_sys_us = 0;

    if (is_wait(lock->cmd) && lock->resume_time != 0 && lock->block_time != 0) {
        elapsed_blocked_us = nsec_to_usec(lock->resume_time - lock->block_time);
        dbg_stat_inc_cmd(FUTEX_WAIT_BLOCKED, lock->cmd);
        if (lock->resume_time <= lock->block_time) {
          dbg_stat_inc(FUTEX_ERROR_NEGATIVE_BLOCK_TIME);
        }
    }
    elapsed_sys_us = nsec_to_usec(timestamp - lock->futex_enter_time)
                       - elapsed_blocked_us;

#if HAS_DEBUG_STATS
    update_debug_stats(lock, elapsed_sys_us, timestamp);
#endif

    // Don't update if missing only one of resume time or block time
    if (is_wait(lock->cmd) &&
        (lock->resume_time == 0) != (lock->block_time == 0)) {
        // Sometime only block_time is updated but not resume time.
        // (Not sure I've ever seen the reverse.)
        // Maybe sched_switch tracepoint doesn't cover all cases?
        return;
    }
    int cur_cpu = bpf_get_smp_processor_id();
    if (elapsed_blocked_us == 0 && cur_cpu != lock->cpu) {
        dbg_stat_inc(ERROR_MISSED_CPU_SWITCH);
        // Sometimes we see a change in cpu without a corresponding context
        // switch. Maybe sched_switch tracepoint doesn't cover all cases?
        return;
    }
    if (!lock->invalid_sys_time && elapsed_sys_us > SYS_TIME_SANITY_THRESHOLD) {
      dbg_stat_inc(ERROR_SYS_TIME_ABOVE_SANITY_THRESHOLD);
      // FIXME: Account for all time
      // Interrupt handlers are definitely part of it, but may also
      // include something else I'm not aware of.
      // It may also be related to the above two cases, but where a thread is
      // resumed on the same cpu as before.
      // Without this, time in sys_futex will be over-reported.
      return;
    }

    struct lock_stats *stats = lookup_lock_stats(pid, tgid, lock);
    if (stats == 0) {
        // Should never happen, but needed to keep compiler happy
        dbg_stat_inc(ERROR_LOCK_STAT_LOOKUP_FAILED);
        return;
    }

    // stats is a pointer into a shared RCU hash table
    // so concurrent updates are not generally safe.
    // But since the tid is part of the key, we know we're
    // the only one updating this entry.
    stats->elapsed_blocked_us += elapsed_blocked_us;
    if (!lock->invalid_sys_time) {
        stats->elapsed_sys_us += elapsed_sys_us;
    }
    if (elapsed_blocked_us > 0) {
        stats->blocked_count++;
        if (elapsed_sys_us > stats->max_sys_us) {
            stats->max_sys_us = elapsed_sys_us;
        }
    }
    if (elapsed_blocked_us > stats->max_blocked_us) {
        stats->max_blocked_us = elapsed_blocked_us;
    }
    if (is_wait(lock->cmd)) {
        stats->wait_count++;
    }
    if (is_wake(lock->cmd)) {
        stats->wake_count++;
    }

    // Histogram of block times
    struct hist_key hist_key = {};
    hist_key.key.uaddr = lock->uaddr;
    hist_key.key.tgid = tgid;
    hist_key.slot = bpf_log2(elapsed_blocked_us);
    dist.increment(hist_key);
}

int on_sched_switch(
    struct tracepoint__sched__sched_switch* args) {

    u32 blocked_pid = args->prev_pid;
    u64 ts = bpf_ktime_get_ns();

    dbg_stat_inc(SCHED_SWITCH);

    // Record the time a thread waiting for a futex goes to sleep
    struct cur_lock *lock;
    if (blocked_pid != 0) {
        // UGLY - kernel uses TASK_STATE_MAX to indicate pre-emption in
        // some cases, maybe to distinguish it from the normal
        // TASK_RUNNING state?
        // WARNING: This will change to TASK_REPORT_MAX in linux 4.14.
        bool preempted = args->prev_state == TASK_RUNNING ||
                         args->prev_state == TASK_STATE_MAX;

        if (preempted) {
            dbg_stat_inc(SCHED_PREEMPT);
        }
        lock = pid_lock.lookup(&blocked_pid);
        if (lock != 0) {
            dbg_stat_inc(FUTEX_SCHED_SWITCH);
            if (preempted) {
                dbg_stat_inc(FUTEX_SCHED_PREEMPT);
            }
            if (lock->block_time != 0) {
                // If more than one context switch happens during a single
                // sys_futex call, we can't accurately calculate system time
                dbg_stat_inc(FUTEX_SCHED_SWITCH_DOUBLE);
                lock->invalid_sys_time = true;
            } else if (is_wake(lock->cmd) || !preempted) {
                // For wake, track preemptions, but for waits ignore them to ensure
                // any blocked period is recorded
                lock->block_time = ts;
            }
        }
    }

    // Record the time a thread resumes running
    u32 next_pid = args->next_pid;
    if (next_pid != 0) {
        lock = pid_lock.lookup(&next_pid);
        if (lock != 0) {
            dbg_stat_inc(SCHED_SWITCH);
            if (lock->block_time != 0) {
                lock->resume_time = ts;
            }
        }
    }

    return 0;
}

int on_enter_futex(
    struct tracepoint__syscalls__sys_enter_futex* args) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;

    if (!(PID_FILTER(tgid)))
            return 0;

    struct cur_lock lock = {};
    lock.uaddr = (u64) args->uaddr;
    lock.tgid = tgid;
    lock.usr_stack_id = usr_stack_traces.get_stackid(
        (struct pt_regs*) args, BPF_F_USER_STACK);
    lock.cmd = args->op & FUTEX_CMD_MASK;
    lock.cpu = bpf_get_smp_processor_id();

    dbg_stat_inc_cmd(FUTEX_ENTER, lock.cmd);

#if HAS_DEBUG_STATS
    struct cur_lock *last_lock = pid_lock.lookup(&pid);
    if (last_lock != 0) {
        dbg_stat_inc_cmd(FUTEX_ERROR_ENTER_TWICE, lock.cmd);
    }
#endif

    lock.futex_enter_time = bpf_ktime_get_ns();
    pid_lock.update(&pid, &lock);
    return 0;
}

int on_exit_futex(
    struct tracepoint__syscalls__sys_exit_futex* args) {
    u64 timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;

    if (!(PID_FILTER(tgid)))
        return 0;

    struct cur_lock *lock = pid_lock.lookup(&pid);
    if (lock != 0) {
        dbg_stat_inc_cmd(FUTEX_EXIT, lock->cmd);
        update_stats(pid, tgid, timestamp, lock);
        pid_lock.delete(&pid);
    } else {
        dbg_stat_inc(FUTEX_EXIT);
        dbg_stat_inc(FUTEX_ERROR_EXIT_NO_ENTRY_RECORD);
    }

    if (args->ret < 0) {
        if (lock != 0) {
            stats_record_error(pid, tgid, lock);
        } else {
            dbg_stat_inc(FUTEX_ERROR_MISSING_RECORD);
        }
    }
    return 0;
}

int on_perf_cycles(struct bpf_perf_event_data *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = (u32) pid_tgid;

    if (!(PID_FILTER(tgid)))
        return 0;

    dbg_stat_inc(SAMPLE_COUNT_CYCLES);

    struct sample_key key;
    key.pid = pid;
    key.pid = 0;
    key.tgid = tgid;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.usr_stack_id = usr_stack_traces.get_stackid(
        &ctx->regs, BPF_F_USER_STACK);
    key.kernel_stack_id = kernel_stack_traces.get_stackid(&ctx->regs, 0);
    cycle_counts.increment(key);
    return 0;
}
