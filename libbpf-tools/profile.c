// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * profile    Profile CPU usage by sampling stack traces at a timed interval.
 * Copyright (c) 2022 LG Electronics
 *
 * Based on profile from BCC by Brendan Gregg and others.
 * 28-Dec-2021   Eunseon Lee   Created this.
 */
#include <argp.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <sys/timerfd.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include "profile.h"
#include "profile.skel.h"
#include "trace_helpers.h"

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

#define pr_format(fd, str, fmt)		dprintf(fd, "%s%s%s", fmt->prefix, str, fmt->suffix)

#define DSO_TIMER_INTERVAL_MS 100

#define US_IN_S  1000000
#define MS_IN_S  1000
#define NS_IN_MS 1000000

#define CPU_PRESSURE_FILE           "/proc/pressure/cpu"
#define MEMORY_PRESSURE_FILE        "/proc/pressure/memory"
#define IO_PRESSURE_FILE            "/proc/pressure/io"

enum {
    FD_PSI_CPU = 0,
    FD_PSI_MEMORY,
    FD_PSI_IO,
    FD_PSI_TIMER,
    FD_DSO_TIMER,
    FD_STOP_TIMER,
    POLL_FD_COUNT
};

int poll_fds[POLL_FD_COUNT];

static struct env {
	pid_t pids[MAX_PID_NR];
	pid_t tids[MAX_TID_NR];
	char *output_path;
	bool user_stacks_only;
	bool kernel_stacks_only;
	bool addrs_only;
	bool refresh_dsos;
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
	int psi_percent;
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
"    profile -P          # run in an infinite loop, triggered by PSI watermarks\n"
"    profile -o /tmp/f   # save output to that file (not stdout)\n"
"    profile -p 185      # only profile process with PID 185\n"
"    profile -L 185      # only profile thread with TID 185\n"
"    profile -U          # only show user space stacks (no kernel)\n"
"    profile -A          # only output addresses\n"
"    profile -R          # refresh DSO list during profiling execution\n"
"    profile -K          # only show kernel space stacks (no user)\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "profile processes with one or more comma-separated PIDs only", 0 },
	{ "tid", 'L', "TID", 0, "profile threads with one or more comma-separated TIDs only", 0 },
	{ "user-stacks-only", 'U', NULL, 0,
	  "show stacks from user space only (no kernel space stacks)", 0 },
	{ "kernel-stacks-only", 'K', NULL, 0,
	  "show stacks from kernel space only (no user space stacks)", 0 },
	{ "addrs-only", 'A', NULL, 0,
	  "output addresses only on final charts (no symbol resolution), also appending extra DSO info section", 0 },
	{ "refresh-dsos", 'R', NULL, 0,
	  "refresh DSO list during profiling execution, not just at its end "
	  "(to catch short-lived processes)", 0 },
	{ "frequency", 'F', "FREQUENCY", 0, "sample frequency, Hertz", 0 },
	{ "delimited", 'd', NULL, 0, "insert delimiter between kernel/user stacks", 0 },
	{ "include-idle ", 'I', NULL, 0, "include CPU idle stacks", 0 },
	{ "folded", 'f', NULL, 0, "output folded format, one line per stack (for flame graphs)", 0 },
	{ "psi-trigger", 'P', "PERCENT", 0, "run [duration] profiling burts in an infinite loop, triggered by this"
	  " PSI watermark (percentage stalled I/O or memory or CPU access over a 1s time window--0 means unset)", 0 },
	{ "output-path", 'o', "PATH", 0, "Path to file(s) where to write output, instead of standard output. "
	  "In case of psi-loop mode, a timestamp suffix will be added, for each run", 0 },
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
volatile bool keep_running = true;

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
	case 'A':
		env.addrs_only = true;
		break;
	case 'R':
		env.refresh_dsos = true;
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
	case 'o':
		env.output_path = strdup(arg);
		break;
	case 'P':
		errno = 0;
		env.psi_percent = strtol(arg, NULL, 10);
		if (errno || env.psi_percent <= 0 || env.psi_percent > 100) {
			fprintf(stderr, "Invalid PSI trigger (percent): %s. Valid range (0-100]\n", arg);
			argp_usage(state);
		}
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
        case ARGP_KEY_END:
		if (env.psi_percent && env.duration == INT_MAX) {
			fprintf(stderr, "invalid duration (infinite) for PSI trigger mode, please set a finite and small time in secs\n");
			argp_usage(state);
		}
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int nr_cpus;

//time_ms == 0 to disarm timer
static int set_timer(int timer_fd, int time_ms, bool repeat)
{
	struct itimerspec timer_spec = {0};
	if (time_ms != 0) {
		timer_spec.it_value.tv_sec = time_ms / MS_IN_S;
		timer_spec.it_value.tv_nsec = (time_ms % MS_IN_S) * NS_IN_MS;
		if (repeat) {
			timer_spec.it_interval.tv_sec = time_ms / MS_IN_S;
			timer_spec.it_interval.tv_nsec = (time_ms % MS_IN_S) * NS_IN_MS;
		}
	}
	if (timerfd_settime(timer_fd, 0, &timer_spec, NULL) == -1) {
		return -errno;
	}
	return 0;
}

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				      struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = env.freq,
		.sample_freq = env.sample_freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	if (env.refresh_dsos) {
		if ((i = set_timer(poll_fds[FD_DSO_TIMER], DSO_TIMER_INTERVAL_MS, true)) < 0)
			return i;
	}

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

static int syms_cache_renew()
{
	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		return -ENOMEM;
	}
	return 0;
}

static int close_and_detach_perf_event(struct profile_bpf *obj, struct bpf_link *links[], bool syms_renew)
{
	int i;
	if (env.refresh_dsos && ((i = set_timer(poll_fds[FD_DSO_TIMER], 0, false) < 0)))
		return i;

	if (env.cpu != -1 && links[env.cpu]) {
		bpf_link__destroy(links[env.cpu]);
		links[env.cpu] = NULL;
	} else {
		for (i = 0; i < nr_cpus; i++) {
			if (!links[i])
				continue;
			bpf_link__destroy(links[i]);
			links[i] = NULL;
		}
	}

	if (syms_cache) {
		syms_cache__free(syms_cache);
		syms_cache = NULL;
		int ret;
		if (syms_renew && (ret = syms_cache_renew()))
			return ret;
		if (!syms_renew) {
			if (ksyms) {
				ksyms__free(ksyms);
				ksyms = NULL;
			}
			profile_bpf__destroy(obj);
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
	keep_running = false;
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
	struct key_t empty = {};
	struct key_t *lookup_key = &empty;
	int i = 0;
	int err;

	while (bpf_map_get_next_key(fd, lookup_key, &items[i].k) == 0) {
		err = bpf_map_lookup_elem(fd, &items[i].k, &items[i].v);
		if (err < 0) {
			fprintf(stderr, "failed to lookup counts: %d\n", err);
			return -err;
		}

		if (items[i].v == 0)
			continue;

		lookup_key = &items[i].k;
		i++;
	}

	*count = i;
	return 0;
}

static const char *ksymname(unsigned long addr)
{
	static char addr_str[32];

	if (env.addrs_only) {
		snprintf(addr_str, sizeof(addr_str), "[0x%lx]", addr);
		return addr_str;
	}

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
	static char addr_str[32];

	if (env.addrs_only) {
		snprintf(addr_str, sizeof(addr_str), "[0x%lx]", addr);
		return addr_str;
	}

	if (!env.verbose) {
		sym = syms__map_addr(syms, addr);
		return sym ? sym->name : "[unknown]";
	}

	return usyminfo(addr);
}

static void print_stacktrace(int fd, unsigned long *ip, symname_fn_t symname, struct fmt_t *f)
{
	int i;

	if (!f->folded) {
		for (i = 0; ip[i] && i < env.perf_max_stack_depth; i++)
			pr_format(fd, symname(ip[i]), f);
		return;
	} else {
		for (i = env.perf_max_stack_depth - 1; i >= 0; i--) {
			if (!ip[i])
				continue;

			pr_format(fd, symname(ip[i]), f);
		}
	}
}

static bool print_user_stacktrace(int fd, struct key_t *event, int stack_map,
				  unsigned long *ip, struct fmt_t *f, bool delim)
{
	if (env.kernel_stacks_only || STACK_ID_EFAULT(event->user_stack_id))
		return false;

	if (delim)
		pr_format(fd, f->delim, f);

	if (bpf_map_lookup_elem(stack_map, &event->user_stack_id, ip) != 0) {
		pr_format(fd, "[Missed User Stack]", f);
	} else {
		syms = syms_cache__get_syms(syms_cache, event->pid);
		if (syms)
			print_stacktrace(fd, ip, usymname, f);
		else if (!f->folded)
			fprintf(stderr, "failed to get syms\n");
	}

	return true;
}

static bool print_kern_stacktrace(int fd, struct key_t *event, int stack_map,
				  unsigned long *ip, struct fmt_t *f, bool delim)
{
	if (env.user_stacks_only || STACK_ID_EFAULT(event->kern_stack_id))
		return false;

	if (delim)
		pr_format(fd, f->delim, f);

	if (bpf_map_lookup_elem(stack_map, &event->kern_stack_id, ip) != 0)
		pr_format(fd, "[Missed Kernel Stack]", f);
	else
		print_stacktrace(fd, ip, ksymname, f);

	return true;
}

static int print_count(int fd, struct key_t *event, __u64 count, int stack_map, bool folded)
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
		ret = print_kern_stacktrace(fd, event, stack_map, ip, fmt, false);
		print_user_stacktrace(fd, event, stack_map, ip, fmt, ret && env.delimiter);
		dprintf(fd, "    %-16s %s (%d)\n", "-", event->name, event->pid);
		dprintf(fd, "        %lld\n\n", count);
	} else {
		/* folded stack output */
		dprintf(fd, "%s", event->name);
		ret = print_user_stacktrace(fd, event, stack_map, ip, fmt, false);
		print_kern_stacktrace(fd, event, stack_map, ip, fmt, ret && env.delimiter);
		dprintf(fd, " %lld\n", count);
	}

	free(ip);

	return 0;
}

static void bump_dso(struct key_t *event, int stack_map, unsigned long *ip)
{
	if (bpf_map_lookup_elem(stack_map, &event->user_stack_id, ip) != 0) {
		return;
	} else {
		syms_cache__get_syms(syms_cache, event->pid);
	}
}

static int refresh_dso(struct key_t *event, int stack_map)
{
	unsigned long *ip;

	ip = calloc(env.perf_max_stack_depth, sizeof(unsigned long));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return -ENOMEM;
	}

	bump_dso(event, stack_map, ip);

	free(ip);

	return 0;
}

static int refresh_dsos(int counts_map, int stack_map)
{
	struct key_ext_t *counts;
	__u32 nr_count = MAX_ENTRIES;
	int i, ret = 0;

	counts = calloc(MAX_ENTRIES, sizeof(struct key_ext_t));
	if (!counts) {
		fprintf(stderr, "Out of memory\n");
		return -ENOMEM;
	}

	ret = read_counts_map(counts_map, counts, &nr_count);
	if (ret)
		goto cleanup;

	for (i = 0; i < nr_count; i++) {
		refresh_dso(&counts[i].k, stack_map);
	}

cleanup:
	free(counts);

	return ret;
}

static void copy_between_fds(int src_fd, int dest_fd) {
    char buffer[PATH_MAX];
    ssize_t bytes;
    while ((bytes = read(src_fd, buffer, sizeof(buffer))) > 0) {
        write(dest_fd, buffer, bytes);
    }
}

static void print_dsos_and_ksyms(int fd)
{
	//separator into next section
	dprintf(fd, "==========\n");
	print_dsos_info(fd, syms_cache);
	//separator again (to accomodate kernel symbols)
	dprintf(fd, "==========\n");
	int proc_fd = open("/proc/kallsyms", O_RDONLY);
	if (proc_fd < 0) {
		perror("Failed to open /proc/kallsyms");
		return;
	}
	//splice and friends seem to hate /proc files, so go with a
	//buffered copy
	copy_between_fds(proc_fd, fd);
	close(proc_fd);
}

static char *compute_path_with_timestamp(const char *path) {
    static char final_path[PATH_MAX];
    char base_path[PATH_MAX], ext[64] = "";
    time_t now;
    struct tm *timeinfo;

    const char *dot = strrchr(path, '.');
    if (dot) {
        snprintf(base_path, dot - path + 1, "%s", path);
        snprintf(ext, sizeof(ext), "%s", dot);
    } else {
        strcpy(base_path, path);
    }

    time(&now);
    timeinfo = localtime(&now);

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", timeinfo);
    snprintf(final_path, sizeof(final_path), "%s_%s%s", base_path, timestamp, ext);

    return final_path;
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

	int fd;
	if (env.output_path) {
		const char *fpath = env.output_path;
		if (env.psi_percent)
			fpath = compute_path_with_timestamp(fpath);
		fd = open(fpath, O_RDWR | O_CREAT | O_TRUNC, 0644);
	} else {
		fd = STDOUT_FILENO;
	}

	for (i = 0; i < nr_count; i++) {
		event = &counts[i].k;
		count = counts[i].v;

		print_count(fd, event, count, stack_map, env.folded);

		/* handle stack id errors */
		nr_missing_stacks += MISSING_STACKS(event->user_stack_id, event->kern_stack_id);
		has_collision = CHECK_STACK_COLLISION(event->user_stack_id, event->kern_stack_id);
	}


	if (env.addrs_only)
		print_dsos_and_ksyms(fd);
	if (env.output_path)
		close(fd);

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

static int setup_timer(int *timer_fd, int epoll_fd) {
	int ret = *timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (ret < 0)
		return -errno;
	struct epoll_event dso_timer_evt = {
		.events = EPOLLIN,
		.data.fd = *timer_fd
	};
	if ((ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, *timer_fd, &dso_timer_evt)) == -1)
		return -errno;

	return 0;
}

static int setup_psi_polling(int epoll_fd) {
	int ret;

	// cumulative stall time over 1s time window
	const float window_percent = env.psi_percent / 100.0;

	ret = poll_fds[FD_PSI_TIMER] = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (ret < 0)
		goto error_epoll;
	struct epoll_event psi_timer_evt = {
		.events = EPOLLIN,
		.data.fd = poll_fds[FD_PSI_TIMER]
	};
	if ((ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, poll_fds[FD_PSI_TIMER], &psi_timer_evt)) == -1)
		goto error_psi_timer;

	char trigger[128];
	ret = poll_fds[FD_PSI_CPU] = open(CPU_PRESSURE_FILE, O_RDWR | O_NONBLOCK);
	if (ret < 0)
		goto error_psi_timer;
	struct epoll_event psi_cpu_evt = {
		.events = EPOLLPRI,
		.data.fd = poll_fds[FD_PSI_CPU]
	};
	snprintf(trigger, 128, "some %d %d", (int) (window_percent * US_IN_S), US_IN_S);
	if ((ret = write(poll_fds[FD_PSI_CPU], trigger, strlen(trigger) + 1)) < 0)
		goto error_psi_cpu;
	if ((ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, poll_fds[FD_PSI_CPU], &psi_cpu_evt)) == -1)
		goto error_psi_cpu;

	ret = poll_fds[FD_PSI_MEMORY] = open(MEMORY_PRESSURE_FILE, O_RDWR | O_NONBLOCK);
	if (ret < 0)
		goto error_psi_cpu;
	struct epoll_event psi_memory_evt = {
		.events = EPOLLPRI,
		.data.fd = poll_fds[FD_PSI_MEMORY]
	};
	snprintf(trigger, 128, "some %d %d", (int) (window_percent * US_IN_S), US_IN_S);
	if ((ret = write(poll_fds[FD_PSI_MEMORY], trigger, strlen(trigger) + 1)) < 0)
		goto error_psi_memory;
	if ((ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, poll_fds[FD_PSI_MEMORY], &psi_memory_evt)) == -1)
		goto error_psi_memory;

	ret = poll_fds[FD_PSI_IO] = open(IO_PRESSURE_FILE, O_RDWR | O_NONBLOCK);
	if (ret < 0)
		goto error_psi_memory;
	struct epoll_event psi_io_evt = {
		.events = EPOLLPRI,
		.data.fd = poll_fds[FD_PSI_IO]
	};
	snprintf(trigger, 128, "some %d %d", (int) (window_percent * US_IN_S), US_IN_S);
	if ((ret = write(poll_fds[FD_PSI_IO], trigger, strlen(trigger) + 1)) < 0)
		goto error_psi_io;
	if ((ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, poll_fds[FD_PSI_IO], &psi_io_evt)) == -1)
		goto error_psi_io;

	return epoll_fd;

 error_psi_io:
	close(poll_fds[FD_PSI_IO]);
 error_psi_memory:
	close(poll_fds[FD_PSI_MEMORY]);
 error_psi_cpu:
	close(poll_fds[FD_PSI_CPU]);
 error_psi_timer:
	close(poll_fds[FD_PSI_TIMER]);
 error_epoll:
	close(epoll_fd);
	return ret;
}

static int main_loop(int epoll_fd, struct profile_bpf *obj, struct bpf_link *links[]) {
	struct epoll_event events[POLL_FD_COUNT];

	/* this loop will only end in SIGINT or errors */
	while (keep_running) {
		int n = epoll_wait(epoll_fd, events, POLL_FD_COUNT, -1);
		if (n < 0) {
			return n;
		}
		for (int i = 0; i < n; i++) {
			if (events[i].data.fd == poll_fds[FD_PSI_TIMER]) {
				int ret = close_and_detach_perf_event(obj, links, true);
				if (ret < 0)
					return ret;

				// reset. this one is only set on PSI fds signalling, see below
				if ((ret = set_timer(poll_fds[FD_PSI_TIMER], 0, false) < 0))
					return ret;

				print_counts(bpf_map__fd(obj->maps.counts),
					     bpf_map__fd(obj->maps.stackmap));
				continue;
			}
			if (events[i].data.fd == poll_fds[FD_DSO_TIMER]) {
				refresh_dsos(bpf_map__fd(obj->maps.counts),
					     bpf_map__fd(obj->maps.stackmap));
				continue;
			}
			if (events[i].data.fd == poll_fds[FD_STOP_TIMER]) {
				keep_running = false;
				continue;
			}
			if (events[i].data.fd == poll_fds[FD_PSI_CPU] ||
			    events[i].data.fd == poll_fds[FD_PSI_MEMORY] ||
			    events[i].data.fd == poll_fds[FD_PSI_IO]) {
				bool skip_to_next = false;

				// profiling in place already, wait
				// for that run to settle first (via
				// timer expiration)
				for (int j = 0; j < nr_cpus; j++) {
					if (links[j] != NULL) {
						skip_to_next = true;
						break;
					}
				}

				if (skip_to_next)
					continue;

				int ret = open_and_attach_perf_event(env.freq, obj->progs.do_perf_event, links);
				if (ret != 0) {
					close_and_detach_perf_event(obj, links, false);
					return ret;
				}

				// one-shot timer
				if ((ret = set_timer(poll_fds[FD_PSI_TIMER], env.duration * MS_IN_S, false) < 0))
					return ret;
			}
		}
	}
	// unreachable
	return 0;
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
	int epoll_fd = 0;
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

	if (syms_cache_renew())
		goto cleanup;

	signal(SIGINT, sig_handler);

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		epoll_fd = 0;
		err = -errno;
		goto cleanup;
	}

	if (env.refresh_dsos) {
		if ((err = setup_timer(&poll_fds[FD_DSO_TIMER], epoll_fd)) < 0)
			goto cleanup;
	}

	/*
	 * We'll get out of the main loop when someone presses Ctrl-C
	 * (which will be handled by sig_handler) or if time is up.
	 */
	if (env.psi_percent) {
		if ((err = setup_psi_polling(epoll_fd)) < 0)
			goto cleanup;
	} else {
		if ((err = open_and_attach_perf_event(env.freq, obj->progs.do_perf_event, links) < 0))
			goto cleanup;
		if ((err = setup_timer(&poll_fds[FD_STOP_TIMER], epoll_fd)) < 0)
			goto cleanup;
		if ((i = set_timer(poll_fds[FD_STOP_TIMER], env.duration * MS_IN_S, false)) < 0)
			goto cleanup;
	}
	main_loop(epoll_fd, obj, links);

	if (!env.folded && !env.psi_percent)
		print_headers();

	if (!env.psi_percent)
		print_counts(bpf_map__fd(obj->maps.counts),
			     bpf_map__fd(obj->maps.stackmap));

cleanup:
	close_and_detach_perf_event(obj, links, false);

	for (i = 0; i < POLL_FD_COUNT; i++) {
		if (poll_fds[i])
			close(poll_fds[i]);
	}

	if (epoll_fd)
		close(epoll_fd);

	return err != 0;
}
