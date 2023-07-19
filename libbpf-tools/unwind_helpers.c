// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Post mortem Dwarf CFI based unwinding on top of regs and stack dumps.
 * Copyright 2023 LG Electronics Inc.
 *
 * Lots of this code have been borrowed or heavily inspired from parts of
 * the libunwind and perf codes.
 * 04-Feb-2023   Eunseon Lee   Created this.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <libunwind-ptrace.h>
#include <errno.h>
#include <dirent.h>
#include "unwind_helpers.h"
#include <unistd.h>
#include <fcntl.h>

/* for internal logs */
#define p_debug(fmt, ...) __p(DEBUG, "Debug", fmt, ##__VA_ARGS__)
#define p_info(fmt, ...) __p(INFO, "Info", fmt, ##__VA_ARGS__)
#define p_warn(fmt, ...) __p(WARN, "Warn", fmt, ##__VA_ARGS__)
#define p_err(fmt, ...) __p(ERROR, "Error", fmt, ##__VA_ARGS__)

enum log_level {
	DEBUG,
	INFO,
	WARN,
	ERROR,
};

static enum log_level log_level = WARN;
static struct sample_data *g_sample;
static size_t sample_stack_size;
struct bpf_object *bpf_obj;
int mem_fd;

void __p(enum log_level level, char *level_str, char *fmt, ...)
{
        va_list ap;

        if (level < log_level)
                return;
        va_start(ap, fmt);
        fprintf(stderr, "%s: ", level_str);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fflush(stderr);
}

/*
 * libunwind address space for post unwinding
 */
#ifndef USE_PTRACE
static int access_dso_mem (unw_word_t addr, unw_word_t *val, pid_t pid)
{
	ssize_t len;

	lseek(mem_fd, addr, SEEK_SET);

	len = read(mem_fd, val, sizeof(*val));
	if (len == -1)
		return -UNW_EINVAL;

	p_debug("mem[%lx] -> %lx\n", (long) addr, (long) *val);
	return 0;
}
#else
static int access_dso_mem (unw_word_t addr, unw_word_t *val, pid_t pid)
{
	int i, end;
	unw_word_t tmp_val;

	/*
	 * Some 32-bit archs have to define a 64-bit unw_word_t.
	 * Callers of this function therefore expect a 64-bit
	 * return value, but ptrace only returns a 32-bit value
	 * in such cases.
	 */
	if (sizeof(long) == 4 && sizeof(unw_word_t) == 8)
		end = 2;
	else
		end = 1;

	for (i = 0; i < end; i++)
	{
		unw_word_t tmp_addr = i == 0 ? addr : addr + 4;
		errno = 0;

		tmp_val = (unsigned long) ptrace (PTRACE_PEEKDATA, pid, tmp_addr, 0);
		if (i == 0)
			*val = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
		*val |= tmp_val << (i * 32);
#else
		*val |= i == 0 && end == 2 ? tmp_val << 32 : tmp_val;
#endif

		if (errno)
			return -UNW_EINVAL;

		p_debug("mem[%lx] -> %lx\n", (long) tmp_addr, (long) tmp_val);
	}
	return 0;
}
#endif

#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)
static inline void* uc_addr (unsigned long uc[], int reg)
{
	return &uc[reg];
}
#else
#error This Architecture is not supported yet. Please open an issue
#endif

static int access_reg(unw_addr_space_t as,
		      unw_regnum_t regnum, unw_word_t *val,
		      int __write, void *arg)
{
	unw_word_t *addr;
	struct sample_data *sample = g_sample;

	/* Don't support write, I suspect we don't need it. */
	if (__write) {
		p_err("unwind: access_reg w %d\n", regnum);
		return -EINVAL;
	}

	if (!(addr = uc_addr ((unsigned long*)&sample->user_regs, regnum))) {
		p_err("unwind: can't read reg %d\n", regnum);
		return -EINVAL;
	}

	*val = *(unw_word_t *) addr;
	p_debug("unwind: reg %d, val %lx\n", regnum, (unsigned long)*val);
	return 0;
}

static int access_mem(unw_addr_space_t as,
		      unw_word_t addr, unw_word_t *valp,
		      int __write, void *arg)
{
	struct sample_data *sample = g_sample;
	struct stack_dump *stack = &sample->user_stack;
	unw_word_t *start;
	unw_word_t end;
	int offset;
	int ret;
	pid_t pid = *(pid_t*)arg;

	/* Don't support write, probably not needed. */
	if (__write || !stack) {
		*valp = 0;
		p_err("unwind: invalid args\n");
		return -EINVAL;
	}

	if (!(start = uc_addr ((unsigned long*)&sample->user_regs, UNW_REG_SP))) {
		p_err("unwind: can't read reg SP\n");
		return -EINVAL;
	}

	end = *(unw_word_t *)start + (unw_word_t)(stack->size);

	/* Check overflow. */
	if (addr + sizeof(unw_word_t) < addr) {
		p_err("unwind: overflow, addr + sizeof(unw_word_t): %lx\n", addr + sizeof(unw_word_t));
		return -EINVAL;
	}

	if (addr < *start || addr + sizeof(unw_word_t) >= end) {
		ret = access_dso_mem(addr, valp, pid);
		if (ret) {
			p_debug("unwind: access_mem %p not inside range"
				" 0x%" PRIx64 "-0x%" PRIx64 "\n",
				(void *) (uintptr_t) addr, start, end);
			*valp = 0;
			return ret;
		}
		return 0;
	}

	offset = addr - *(unw_word_t *)start;
	*valp = *(unw_word_t *)&stack->data[offset];
	p_debug("unwind: start: %lx, end: %lx, addr: %p, offset: %lx\n",
		(unsigned long)*start, (unsigned long)end, (void*)(uintptr_t)addr, offset);
	p_debug("unwind: access_mem addr %p val %lx, offset %d\n",
	        (void *) (uintptr_t) addr, (unsigned long)*valp, offset);
	return 0;
}

static unw_accessors_t accessors = {
	.find_proc_info = _UPT_find_proc_info,
	.put_unwind_info = _UPT_put_unwind_info,
	.get_dyn_info_list_addr = _UPT_get_dyn_info_list_addr,
	.access_mem = access_mem,
	.access_reg = access_reg,
	.access_fpreg = _UPT_access_fpreg,
	.resume = _UPT_resume,
	.get_proc_name = _UPT_get_proc_name,
};


static int get_entries(const struct sample_data *sample, pid_t pid,
		       unsigned long *ip, int count)
{
	unw_cursor_t cursor;
	void *context = NULL;
	int err = 0;
	int i = 0;
	unw_addr_space_t as = unw_create_addr_space(&accessors, 0);

	if (!sample || !ip)
		return -EINVAL;

	g_sample = sample;

#ifdef USE_PTRACE
	if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
		p_err("ERROR: cannot attach to %d\n", pid);
		return -1;
	}
#endif

	context = _UPT_create(pid);
	if (!context) {
		err = -1;
		goto cleanup;
	}

	if (unw_init_remote(&cursor, as, context) != 0) {
		p_err("ERROR: cannot initialize cursor for remote unwinding\n");
		return -1;
	}

	do {
		unw_word_t pc;
		if (unw_get_reg(&cursor, UNW_REG_IP, &pc)) {
			p_err("ERROR: cannot read program counter\n");
			return -1;
		}

		ip[i++] = pc;
	} while (unw_step(&cursor) > 0 && i < count);

	printf("%s, err: %d\n", __FUNCTION__, err);
#if 0
	} while (((err = unw_step(&cursor)) > 0) && i < count);
	if (err > 0)
		err = -ENOBUFS;
#endif

cleanup:
	if (context)
		_UPT_destroy(context);

#ifdef USE_PTRACE
	(void) ptrace(PTRACE_DETACH, pid, 0, 0);
#endif

	return err;
}

static inline unw_word_t stack_pointer(unsigned long uc[])
{
	return *(unw_word_t*)uc_addr(uc, UNW_REG_SP);
}

static void dump_stack(char* stack, size_t len)
{
	p_debug("stack data: \n");
	for (int i = 0; i < len; i++)
		p_debug("[%d]: %x ", i, stack[i*sizeof(long)]);
	p_debug("\n");
}

static void dump_regs(regs_dump_t *user_regs)
{
	p_debug("regs: \n");
	for (int i = 0; i <= UNW_REG_LAST; i++)
		p_debug("regs[%d]: 0x%llx\n", i, user_regs[i]);
}

static void dump_sample(const int stack_id, struct sample_data *sample)
{
	p_debug("post unwind for stack %d\n", stack_id);
	dump_regs(&sample->user_regs);
	dump_stack(sample->user_stack.data, 20);
}

int uw_map_lookup_elem(const int *stack_id, pid_t pid,
		       unsigned long *ip, size_t count)
{
	int samples_map, ustacks_map;
	struct sample_data *sample = NULL;
	char *sample_ustack = NULL;
	char mem_path[256];
	int err;

#ifndef USE_PTRACE
	snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
	mem_fd = open(mem_path, O_RDONLY);
	if (mem_fd == -1) {
		p_err("failed to open %s: %s", mem_path, strerror(errno));
		return -EINVAL;
	}
#endif

	sample = (struct sample_data*)malloc(sizeof(struct sample_data));
	if (!sample)
		return -ENOMEM;

	sample_ustack = (char*)malloc(sample_stack_size);
	if (!sample_ustack) {
		err = -ENOMEM;
		goto cleanup;
	}

	samples_map = bpf_map__fd(bpf_object__find_map_by_name(bpf_obj, NAME(UW_SAMPLES_MAP)));
	if (samples_map < 0) {
		err = samples_map;
		goto cleanup;
	}
	ustacks_map = bpf_map__fd(bpf_object__find_map_by_name(bpf_obj, NAME(UW_STACKS_MAP)));
	if (ustacks_map < 0) {
		err = ustacks_map;
		goto cleanup;
	}

	err = bpf_map_lookup_elem(samples_map, stack_id, sample);
	if (err < 0) {
		fprintf(stderr, "failed to lookup samples for stack %d: %d\n", *stack_id, err);
		goto cleanup;
	}

	err = bpf_map_lookup_elem(ustacks_map, stack_id, sample_ustack);
	if (err < 0) {
		fprintf(stderr, "failed to lookup ustacks for stack %d: %d\n", *stack_id, err);
		goto cleanup;
	}
	sample->user_stack.data = sample_ustack;

	dump_sample(*stack_id, sample);

	err = get_entries(sample, pid, ip, count);
	if (err)
		p_err("get_entries failded: %d\n", err);

cleanup:
	if (sample->user_stack.data)
		free(sample->user_stack.data);
	if (sample)
		free(sample);

	return err;
}

int uw_map__set(const struct bpf_object *obj, size_t stack_size, size_t max_entries)
{
	struct bpf_map *samples_map = bpf_object__find_map_by_name(obj, NAME(UW_SAMPLES_MAP));
	struct bpf_map *ustacks_map = bpf_object__find_map_by_name(obj, NAME(UW_STACKS_MAP));

	if (samples_map < 0 || ustacks_map < 0)
		return -EINVAL;

	/* set max entries of bpf sample map */
	bpf_map__set_max_entries(samples_map, max_entries);

	/* set value size and max entries of bpf ustack map */
	bpf_map__set_value_size(ustacks_map, stack_size);
	bpf_map__set_max_entries(ustacks_map, max_entries);

	sample_stack_size = stack_size;
	bpf_obj = obj;

	return 0;
}
