// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * profile    Profile CPU usage by sampling stack traces at a timed interval.
 * Copyright (c) 2022 LG Electronics
 *
 * Based on profile from BCC by Brendan Gregg and others.
 * 28-Dec-2021   Eunseon Lee   Created this.
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include "profile.h"
#include "profile.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

#define SYM_INFO_LEN			2048

/*
 * -EFAULT in get_stackid normally means the stack-trace is not available,
 * such as getting kernel stack trace in user mode
 */
#define STACK_ID_EFAULT(stack_id)	(stack_id == -EFAULT)

#define STACK_ID_ERR(stack_id)		((stack_id < 0) && !STACK_ID_EFAULT(stack_id))

/* hash collision (-EEXIST) suggests that stack map size may be too small */
#define CHECK_STACK_COLLISION(ustack_id, kstack_id)	\
	(kstack_id == -EEXIST || ustack_id == -EEXIST)

#define MISSING_STACKS(ustack_id, kstack_id)	\
	(!env.user_stacks_only && STACK_ID_ERR(kstack_id)) + (!env.kernel_stacks_only && STACK_ID_ERR(ustack_id))

/* This structure combines key_t and count which should be sorted together */
struct key_ext_t {
	struct key_t k;
	__u64 v;
};

typedef const char* (*symname_fn_t)(unsigned long);

/* This structure represents output format-dependent attributes. */
struct fmt_t {
	bool folded;
	char *prefix;
	char *suffix;
	char *delim;
};

struct fmt_t stacktrace_formats[] = {
	{ false, "    ", "\n", "--" },	/* multi-line */
	{ true, ";", "", "-" }		/* folded */
};

#define pr_format(str, fmt)		printf("%s%s%s", fmt->prefix, str, fmt->suffix)

static struct env {
	pid_t pids[MAX_PID_NR];
	pid_t tids[MAX_TID_NR];
	bool user_stacks_only;
	bool kernel_stacks_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	int duration;
	bool verbose;
	bool freq;
	int sample_freq;
	bool delimiter;
	bool include_idle;
	int cpu;
	bool folded;
} env = {
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.duration = INT_MAX,
	.freq = 1,
	.sample_freq = 49,
	.cpu = -1,
};

const char *argp_program_version = "profile 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Profile CPU usage by sampling stack traces at a timed interval.\n"
"\n"
"USAGE: profile [OPTIONS...] [duration]\n"
"EXAMPLES:\n"
"    profile             # profile stack traces at 49 Hertz until Ctrl-C\n"
"    profile -F 99       # profile stack traces at 99 Hertz\n"
"    profile -c 1000000  # profile stack traces every 1 in a million events\n"
"    profile 5           # profile at 49 Hertz for 5 seconds only\n"
"    profile -f          # output in folded format for flame graphs\n"
"    profile -p 185      # only profile process with PID 185\n"
"    profile -L 185      # only profile thread with TID 185\n"
"    profile -U          # only show user space stacks (no kernel)\n"
"    profile -K          # only show kernel space stacks (no user)\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "profile processes with one or more comma-separated PIDs only", 0 },
	{ "tid", 'L', "TID", 0, "profile threads with one or more comma-separated TIDs only", 0 },
	{ "user-stacks-only", 'U', NULL, 0,
	  "show stacks from user space only (no kernel space stacks)", 0 },
	{ "kernel-stacks-only", 'K', NULL, 0,
	  "show stacks from kernel space only (no user space stacks)", 0 },
	{ "frequency", 'F', "FREQUENCY", 0, "sample frequency, Hertz", 0 },
	{ "delimited", 'd', NULL, 0, "insert delimiter between kernel/user stacks", 0 },
	{ "include-idle ", 'I', NULL, 0, "include CPU idle stacks", 0 },
	{ "folded", 'f', NULL, 0, "output folded format, one line per stack (for flame graphs)", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)", 0 },
	{ "cpu", 'C', "CPU", 0, "cpu number to run profile on", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

struct ksyms *ksyms;
struct syms_cache *syms_cache;
struct syms *syms;
static char syminfo[SYM_INFO_LEN];

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int ret;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		ret = split_convert(strdup(arg), ",", env.pids, sizeof(env.pids),
				    sizeof(pid_t), str_to_int);
		if (ret) {
			if (ret == -ENOBUFS)
				fprintf(stderr, "the number of pid is too big, please "
					"increase MAX_PID_NR's value and recompile\n");
			else
				fprintf(stderr, "invalid PID: %s\n", arg);

			argp_usage(state);
		}
		break;
	case 'L':
		ret = split_convert(strdup(arg), ",", env.tids, sizeof(env.tids),
				    sizeof(pid_t), str_to_int);
		if (ret) {
			if (ret == -ENOBUFS)
				fprintf(stderr, "the number of tid is too big, please "
					"increase MAX_TID_NR's value and recompile\n");
			else
				fprintf(stderr, "invalid TID: %s\n", arg);

			argp_usage(state);
		}
		break;
	case 'U':
		env.user_stacks_only = true;
		break;
	case 'K':
		env.kernel_stacks_only = true;
		break;
	case 'F':
		errno = 0;
		env.sample_freq = strtol(arg, NULL, 10);
		if (errno || env.sample_freq <= 0) {
			fprintf(stderr, "invalid FREQUENCY: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		env.delimiter = true;
		break;
	case 'I':
		env.include_idle = true;
		break;
	case 'C':
		errno = 0;
		env.cpu = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid CPU: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'f':
		env.folded = true;
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration (in s): %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(struct bpf_program *prog,
				      struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = env.freq,
		.sample_freq = env.sample_freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		if (env.cpu != -1 && env.cpu != i)
			continue;

		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;

			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}

		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			fprintf(stderr, "failed to attach perf event on cpu: "
				"%d\n", i);
			links[i] = NULL;
			close(fd);
			return -1;
		}
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
}

static int cmp_counts(const void *a, const void *b)
{
	const __u64 x = ((struct key_ext_t *) a)->v;
	const __u64 y = ((struct key_ext_t *) b)->v;

	/* descending order */
	return y - x;
}

static int read_counts_map(int fd, struct key_ext_t *items, __u32 *count)
{
	struct key_t keys[*count];
	__u64 vals[*count];
	__u32 key_size = sizeof(keys[0]);
	__u32 value_size = sizeof(__u64);
	struct key_t empty = {};
	int i = 0;
	int err;
	__u32 n = *count;

	err = dump_hash(fd, keys, key_size, vals, value_size, &n, &empty);
	if (err)
		return err;

	for (i = 0; i < n; i++) {
		items[i].k.pid = keys[i].pid;
		items[i].k.user_stack_id = keys[i].user_stack_id;
		items[i].k.kern_stack_id = keys[i].kern_stack_id;
		strncpy(items[i].k.name, keys[i].name, TASK_COMM_LEN);
		items[i].v = vals[i];
	}

	*count = n;

	return 0;
}

static const char *ksymname(unsigned long addr)
{
	const struct ksym *ksym = ksyms__map_addr(ksyms, addr);

	if (!env.verbose)
		return ksym ? ksym->name : "[unknown]";

	if (ksym)
		snprintf(syminfo, SYM_INFO_LEN, "0x%lx %s+0x%lx", addr,
			 ksym->name, addr - ksym->addr);
	else
		snprintf(syminfo, SYM_INFO_LEN, "0x%lx [unknown]", addr);

	return syminfo;
}

static const char *usyminfo(unsigned long addr)
{
	struct sym_info sinfo;
	int err;
	int c;

	c = snprintf(syminfo, SYM_INFO_LEN, "0x%016lx", addr);

	err = syms__map_addr_dso(syms, addr, &sinfo);
	if (err == 0) {
		if (sinfo.sym_name) {
			c += snprintf(syminfo + c, SYM_INFO_LEN - c, " %s+0x%lx",
				      sinfo.sym_name, sinfo.sym_offset);
		}

		snprintf(syminfo + c, SYM_INFO_LEN - c, " (%s+0x%lx)",
			 sinfo.dso_name, sinfo.dso_offset);
	}

	return syminfo;
}

static const char *usymname(unsigned long addr)
{
	const struct sym *sym;

	if (!env.verbose) {
		sym = syms__map_addr(syms, addr);
		return sym ? sym->name : "[unknown]";
	}

	return usyminfo(addr);
}

static void print_stacktrace(unsigned long *ip, symname_fn_t symname, struct fmt_t *f)
{
	int i;

	if (!f->folded) {
		for (i = 0; ip[i] && i < env.perf_max_stack_depth; i++)
			pr_format(symname(ip[i]), f);
		return;
	} else {
		for (i = env.perf_max_stack_depth - 1; i >= 0; i--) {
			if (!ip[i])
				continue;

			pr_format(symname(ip[i]), f);
		}
	}
}

static bool print_user_stacktrace(struct key_t *event, int stack_map,
				  unsigned long *ip, struct fmt_t *f, bool delim)
{
	if (env.kernel_stacks_only || STACK_ID_EFAULT(event->user_stack_id))
		return false;

	if (delim)
		pr_format(f->delim, f);

	if (bpf_map_lookup_elem(stack_map, &event->user_stack_id, ip) != 0) {
		pr_format("[Missed User Stack]", f);
	} else {
		syms = syms_cache__get_syms(syms_cache, event->pid);
		if (syms)
			print_stacktrace(ip, usymname, f);
		else if (!f->folded)
			fprintf(stderr, "failed to get syms\n");
	}

	return true;
}

static bool print_kern_stacktrace(struct key_t *event, int stack_map,
				  unsigned long *ip, struct fmt_t *f, bool delim)
{
	if (env.user_stacks_only || STACK_ID_EFAULT(event->kern_stack_id))
		return false;

	if (delim)
		pr_format(f->delim, f);

	if (bpf_map_lookup_elem(stack_map, &event->kern_stack_id, ip) != 0)
		pr_format("[Missed Kernel Stack]", f);
	else
		print_stacktrace(ip, ksymname, f);

	return true;
}

static int print_count(struct key_t *event, __u64 count, int stack_map, bool folded)
{
	unsigned long *ip;
	int ret;
	struct fmt_t *fmt = &stacktrace_formats[folded];

	ip = calloc(env.perf_max_stack_depth, sizeof(unsigned long));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return -ENOMEM;
	}

	if (!folded) {
		/* multi-line stack output */
		ret = print_kern_stacktrace(event, stack_map, ip, fmt, false);
		print_user_stacktrace(event, stack_map, ip, fmt, ret && env.delimiter);
		printf("    %-16s %s (%d)\n", "-", event->name, event->pid);
		printf("        %lld\n\n", count);
	} else {
		/* folded stack output */
		printf("%s", event->name);
		ret = print_user_stacktrace(event, stack_map, ip, fmt, false);
		print_kern_stacktrace(event, stack_map, ip, fmt, ret && env.delimiter);
		printf(" %lld\n", count);
	}

	free(ip);

	return 0;
}

static int print_counts(int counts_map, int stack_map)
{
	struct key_ext_t *counts;
	struct key_t *event;
	__u64 count;
	__u32 nr_count = MAX_ENTRIES;
	size_t nr_missing_stacks = 0;
	bool has_collision = false;
	int i, ret = 0;

	counts = calloc(MAX_ENTRIES, sizeof(struct key_ext_t));
	if (!counts) {
		fprintf(stderr, "Out of memory\n");
		return -ENOMEM;
	}

	ret = read_counts_map(counts_map, counts, &nr_count);
	if (ret)
		goto cleanup;

	qsort(counts, nr_count, sizeof(struct key_ext_t), cmp_counts);

	for (i = 0; i < nr_count; i++) {
		event = &counts[i].k;
		count = counts[i].v;

		print_count(event, count, stack_map, env.folded);

		/* handle stack id errors */
		nr_missing_stacks += MISSING_STACKS(event->user_stack_id, event->kern_stack_id);
		has_collision = CHECK_STACK_COLLISION(event->user_stack_id, event->kern_stack_id);
	}

	if (nr_missing_stacks > 0) {
		fprintf(stderr, "WARNING: %zu stack traces could not be displayed.%s\n",
			nr_missing_stacks, has_collision ?
			" Consider increasing --stack-storage-size.":"");
	}

cleanup:
	free(counts);

	return ret;
}

static int set_pidns(const struct profile_bpf *obj)
{
	struct stat statbuf;

	if (!probe_bpf_ns_current_pid_tgid())
		return -EPERM;

	if (stat("/proc/self/ns/pid", &statbuf) == -1)
		return -errno;

	obj->rodata->use_pidns = true;
	obj->rodata->pidns_dev = statbuf.st_dev;
	obj->rodata->pidns_ino = statbuf.st_ino;

	return 0;
}

static void print_headers()
{
	int i;

	printf("Sampling at %d Hertz of", env.sample_freq);

	if (env.pids[0]) {
		printf(" PID [");
		for (i = 0; i < MAX_PID_NR && env.pids[i]; i++)
			printf("%d%s", env.pids[i], (i < MAX_PID_NR - 1 && env.pids[i + 1]) ? ", " : "]");
	} else if (env.tids[0]) {
		printf(" TID [");
		for (i = 0; i < MAX_TID_NR && env.tids[i]; i++)
			printf("%d%s", env.tids[i], (i < MAX_TID_NR - 1 && env.tids[i + 1]) ? ", " : "]");
	} else {
		printf(" all threads");
	}

	if (env.user_stacks_only)
		printf(" by user");
	else if (env.kernel_stacks_only)
		printf(" by kernel");
	else
		printf(" by user + kernel");

	if (env.cpu != -1)
		printf(" on CPU#%d", env.cpu);

	if (env.duration < INT_MAX)
		printf(" for %d secs.\n", env.duration);
	else
		printf("... Hit Ctrl-C to end.\n");
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_link *links[MAX_CPU_NR] = {};
	struct profile_bpf *obj;
	int pids_fd, tids_fd;
	int err, i;
	__u8 val = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.user_stacks_only && env.kernel_stacks_only) {
		fprintf(stderr, "user_stacks_only and kernel_stacks_only cannot be used together.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		printf("failed to get # of possible cpus: '%s'!\n",
		       strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		fprintf(stderr, "the number of cpu cores is too big, please "
			"increase MAX_CPU_NR's value and recompile");
		return 1;
	}

	obj = profile_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->user_stacks_only = env.user_stacks_only;
	obj->rodata->kernel_stacks_only = env.kernel_stacks_only;
	obj->rodata->include_idle = env.include_idle;
	if (env.pids[0])
		obj->rodata->filter_by_pid = true;
	else if (env.tids[0])
		obj->rodata->filter_by_tid = true;

	bpf_map__set_value_size(obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = set_pidns(obj);
	if (err && env.verbose)
		fprintf(stderr, "failed to translate pidns: %s\n", strerror(-err));

	err = profile_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		goto cleanup;
	}

	if (env.pids[0]) {
		pids_fd = bpf_map__fd(obj->maps.pids);
		for (i = 0; i < MAX_PID_NR && env.pids[i]; i++) {
			if (bpf_map_update_elem(pids_fd, &(env.pids[i]), &val, BPF_ANY) != 0) {
				fprintf(stderr, "failed to init pids map: %s\n", strerror(errno));
				goto cleanup;
			}
		}
	}
	else if (env.tids[0]) {
		tids_fd = bpf_map__fd(obj->maps.tids);
		for (i = 0; i < MAX_TID_NR && env.tids[i]; i++) {
			if (bpf_map_update_elem(tids_fd, &(env.tids[i]), &val, BPF_ANY) != 0) {
				fprintf(stderr, "failed to init tids map: %s\n", strerror(errno));
				goto cleanup;
			}
		}
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}

	err = open_and_attach_perf_event(obj->progs.do_perf_event, links);
	if (err)
		goto cleanup;

	signal(SIGINT, sig_handler);

	if (!env.folded)
		print_headers();

	/*
	 * We'll get sleep interrupted when someone presses Ctrl-C.
	 * (which will be "handled" with noop by sig_handler)
	 */
	sleep(env.duration);

	print_counts(bpf_map__fd(obj->maps.counts),
		     bpf_map__fd(obj->maps.stackmap));

cleanup:
	if (env.cpu != -1)
		bpf_link__destroy(links[env.cpu]);
	else {
		for (i = 0; i < nr_cpus; i++)
			bpf_link__destroy(links[i]);
	}
	if (syms_cache)
		syms_cache__free(syms_cache);
	if (ksyms)
		ksyms__free(ksyms);
	profile_bpf__destroy(obj);

	return err != 0;
}
