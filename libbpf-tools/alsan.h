/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright 2022 LG Electronics Inc. */
#ifndef __ALSAN_H
#define __ALSAN_H

#define MAX_ENTRIES 65536

/*
 * The size of memptrs and sizes map is sufficient if it is larger than the
 * number of concurrent thread. If target process runs more threads than
 * MAX_THREAD_NUM, it is recommended to increase it
 */
#define MAX_THREAD_NUM 128

enum chunk_tag {
	DIRECTLY_LEAKED = 0,
	INDIRECTLY_LEAKED = 1,
	REACHABLE = 2,
	IGNORED = 3
};

struct alsan_info_t {
	__u64 size;
	int stack_id;
	enum chunk_tag tag;
};

#endif /* __ALSAN_H */
