/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TRACE_HELPERS_H
#define __TRACE_HELPERS_H

#include <stdbool.h>

#define NSEC_PER_SEC		1000000000ULL

struct ksym {
	const char *name;
	unsigned long addr;
};

struct ksyms;

struct ksyms *ksyms__load(void);
void ksyms__free(struct ksyms *ksyms);
const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr);
const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name);

struct sym {
	const char *name;
	unsigned long start;
	unsigned long size;
	unsigned long offset;
};

struct sym_info {
	const char *dso_name;
	unsigned long dso_offset;
	const char *sym_name;
	unsigned long sym_offset;
};

struct syms;

struct syms *syms__load_pid(int tgid);
struct syms *syms__load_file(const char *fname, pid_t tgid);
void syms__free(struct syms *syms);
const struct sym *syms__map_addr(const struct syms *syms, unsigned long addr);
int syms__map_addr_dso(const struct syms *syms, unsigned long addr,
		       struct sym_info *sinfo);

struct syms_cache;

struct syms_cache *syms_cache__new(int nr);
struct syms *syms_cache__get_syms(struct syms_cache *syms_cache, int tgid);
void syms_cache__free(struct syms_cache *syms_cache);

struct partition {
	char *name;
	unsigned int dev;
};

struct partitions;

struct partitions *partitions__load(void);
void partitions__free(struct partitions *partitions);
const struct partition *
partitions__get_by_dev(const struct partitions *partitions, unsigned int dev);
const struct partition *
partitions__get_by_name(const struct partitions *partitions, const char *name);

void print_dsos_info(int fd, struct syms_cache *syms_cache);
void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type);
void print_linear_hist(unsigned int *vals, int vals_size, unsigned int base,
		unsigned int step, const char *val_type);

unsigned long long get_ktime_ns(void);

bool is_kernel_module(const char *name);

/*
 * When attempting to use kprobe/kretprobe, please check out new fentry/fexit
 * probes, as they provide better performance and usability. But in some
 * situations we have to fallback to kprobe/kretprobe probes. This helper
 * is used to detect fentry/fexit support for the specified kernel function.
 *
 *	1. A gap between kernel versions, kernel BTF is exposed
 * 	   starting from 5.4 kernel. but fentry/fexit is actually
 * 	   supported starting from 5.5.
 *	2. Whether kernel supports module BTF or not
 *
 * *name* is the name of a kernel function to be attached to, which can be
 * from vmlinux or a kernel module.
 * *mod* is a hint that indicates the *name* may reside in module BTF,
 * if NULL, it means *name* belongs to vmlinux.
 */
bool fentry_can_attach(const char *name, const char *mod);

/*
 * The name of a kernel function to be attached to may be changed between
 * kernel releases. This helper is used to confirm whether the target kernel
 * uses a certain function name before attaching.
 *
 * It is achieved by scaning
 * 	/sys/kernel/debug/tracing/available_filter_functions
 * If this file does not exist, it fallbacks to parse /proc/kallsyms,
 * which is slower.
 */
bool kprobe_exists(const char *name);
bool tracepoint_exists(const char *category, const char *event);

bool vmlinux_btf_exists(void);
bool module_btf_exists(const char *mod);

bool probe_tp_btf(const char *name);
bool probe_ringbuf();
bool probe_bpf_ns_current_pid_tgid(void);

typedef int (*convert_fn_t)(const char *src, void *dest);
int split_convert(char *s, const char* delim, void *elems, size_t elems_size,
		  size_t elem_size, convert_fn_t convert);
/*
 * Implementations of convert_fn_t.
 * This can be replaced with a user-defined callback function.
 */
/* converts a string to an integer */
int str_to_int(const char *src, void *dest);
/* converts a string to a long integer */
int str_to_long(const char *src, void *dest);

#endif /* __TRACE_HELPERS_H */
