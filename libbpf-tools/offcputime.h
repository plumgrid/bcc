/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OFFCPUTIME_H
#define __OFFCPUTIME_H

#define TASK_COMM_LEN		16
#define MAX_ENTRIES		10240

struct key_t {
	__u32 pid;
	__u32 tgid;
	int user_stack_id;
	int kern_stack_id;
};

struct val_t {
	__u64 delta;
	char comm[TASK_COMM_LEN];
};

#endif /* __OFFCPUTIME_H */
