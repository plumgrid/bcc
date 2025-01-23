// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __PROFILE_H
#define __PROFILE_H

#define TASK_COMM_LEN		16
#define MAX_CPU_NR		128
#define MAX_ENTRIES		10240
#define MAX_PID_NR		30
#define MAX_TID_NR		30

struct key_t {
	__u32 pid;
	int user_stack_id;
	int kern_stack_id;
	char name[TASK_COMM_LEN];
};

#endif /* __PROFILE_H */
