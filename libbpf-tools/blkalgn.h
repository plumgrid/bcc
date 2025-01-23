/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 Samsung */
#ifndef __BLKALGN_H
#define __BLKALGN_H

#define MAX_FILENAME_LEN 127
#define NAME_LEN 32
#define TASK_COMM_LEN 16

#define MAX_SLOTS 4096

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

struct hkey {
	char disk[NAME_LEN];
};

struct hval {
	__u32 slots[MAX_SLOTS];
};

struct event {
	char comm[TASK_COMM_LEN];
	char disk[NAME_LEN];
	int pid;
	unsigned flags;
	unsigned lbs;
	unsigned len;
	unsigned long long sector;
};

#endif /* __BLKALGN_H */
