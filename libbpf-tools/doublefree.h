/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright 2022 LG Electronics Inc. */
#ifndef __DOUBLEFREE_H
#define __DOUBLEFREE_H

#define MAX_ENTRIES 65536

struct event {
	int err; /* success: 0, failure: -1 */
	int stackid;
	__u64 addr;
};

struct doublefree_info_t {
	int stackid;
	/* allocated: 1, deallocated: 0, doublefreed: -1 */
	int alloc_count;
};

#endif /* __DOUBLEFREE_H */
