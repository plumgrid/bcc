/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __SCHEDTIMES_H
#define __SCHEDTIMES_H

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct sched_times_t {
    char comm[TASK_COMM_LEN];
    __u64 run_time;
    __u64 sleep_time;
	__u64 queue_time;
	__u64 block_time;
	__u32 key;
};

enum task_state {
	STATE_SLEEPING,
	STATE_BLOCKED,
	STATE_QUEUED,
	STATE_RUNNING
};

struct state_ts_t {
	__u64 ts;
	enum task_state state;
};

#endif /* __SCHEDTIMES_H */
