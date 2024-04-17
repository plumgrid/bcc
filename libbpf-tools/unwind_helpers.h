// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright 2023 LG Electronics Inc.
#ifndef __UNWIND_HELPERS_H
#define __UNWIND_HELPERS_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <libunwind-ptrace.h>
#include "unwind_types.h"
/*
 * How to use
 *
 * In case of hello tool,
 *
 * for hello.bpf.c
 * 1. include unwind.bpf.h
 * 2. can use uw_get_stackid to get stackid
 *
 * for hello.c
 * 1. include unwind_helpers.h
 * 2. call UW_INIT before calling *_bpf__load to init resource sizes in unwind_helper.
 * 3. call uw_map_lookup_elem to get ips for stack id.
 *
 * regs dump and stack dumps are stored in internal maps in unwind_helpers which size can be configurable by UW_INIT.
 */

/*
 * UW_INIT(obj, stack_size, uw_max_entries)
 *
 * @obj: bpf_object
 * @stack_size: max size to store each user stack
 * @uw_max_entries: max entries to store user stacks
 */
#define UW_INIT(obj, stack_size, uw_max_entries) 		\
({									\
	obj->rodata->post_unwind = true; 				\
	obj->rodata->sample_ustack_size = stack_size; 		\
	obj->rodata->sample_max_entries = uw_max_entries;	 	\
	uw_map__set(obj->obj, stack_size, uw_max_entries);	\
})

int uw_map__set(const struct bpf_object *obj, size_t stack_size, size_t max_entries);

/*
 * uw_map_lookup_elem
 *
 * allows to lookup BPF map value corresponding to provided key.
 *
 * @brief **bpf_map__lookup_elem()** allows to lookup BPF map value
 * corresponding to provided key.
 * @ustack_id: user stack id to lookup and unwind
 * @pid: process id of @key
 * @ip: pointer to memory in which unwounded value will be stored
 * @count: number of value data memory
 *
 * This function returns id of dumped user stack and registers for current context
 * 	Perform a lookup in *map* for an entry associated to *key*.
 */
int uw_map_lookup_elem(const int *stack_id, pid_t pid,
		       unsigned long *ip, size_t count);

#endif /* __UNWIND_HELPERS_H */
