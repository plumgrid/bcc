// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Copyright 2024 Sony Group Corporation

#ifndef __FILEGONE_H
#define __FILEGONE_H

#define DNAME_INLINE_LEN	32
#define TASK_COMM_LEN		16

struct event {
	char fname[DNAME_INLINE_LEN];
	char fname2[DNAME_INLINE_LEN];
	char task[TASK_COMM_LEN];
	__u8 action;
	pid_t tgid;
};

#endif /* __FILEGONE_H */
