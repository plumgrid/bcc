/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright 2022 LG Electronics Inc. */

// 19-Oct-2022   Bojun Seo   Created this.
#include <argp.h>
#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "doublefree.h"
#include "doublefree.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define STACK_DEPTH 127
#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 10000
#define CHECK_FAIL true
#define DATE_FORMAT "%2d-%s-%02d %02d:%02d:%02d "

#define p_debug(fmt, ...) __p(stderr, DEBUG, "DEBUG", fmt, ##__VA_ARGS__)
#define p_info(fmt, ...) __p(stderr, INFO, "INFO", fmt, ##__VA_ARGS__)
#define p_warn(fmt, ...) __p(stderr, WARN, "WARN", fmt, ##__VA_ARGS__)
#define p_err(fmt, ...) __p(stderr, ERROR, "ERROR", fmt, ##__VA_ARGS__)

#define UPROBE_ELEM(func_name, check_fail) \
	{ \
		.links = obj->links.func_name##_entry, \
		.prog = obj->progs.func_name##_entry, \
		.pid = env.pid, \
		.name = #func_name, \
		.lib_path = libc_path, \
		.is_ret = false, \
		.check = check_fail, \
	},

#define URETPROBE_ELEM(func_name, check_fail) \
	{ \
		.links = obj->links.func_name##_return, \
		.prog = obj->progs.func_name##_return, \
		.pid = env.pid, \
		.name = #func_name, \
		.lib_path = libc_path, \
		.is_ret = true, \
		.check = check_fail, \
	},

#define UPROBE_ELEMS(func_name, check_fail) \
		UPROBE_ELEM(func_name, check_fail) \
		URETPROBE_ELEM(func_name, check_fail)

struct probe {
	struct bpf_link *links;
	struct bpf_program *prog;
	pid_t pid;
	const char *name;
	const char *lib_path;
	bool is_ret;
	bool check;
};

enum log_level {
	DEBUG,
	INFO,
	WARN,
	ERROR,
};

static volatile sig_atomic_t exiting = 0;

static struct env {
	pid_t pid;
	int stack_storage_size;
	int perf_max_stack_depth;
	bool verbose;
	char *command;
} env = {
	.pid = -1,
	.stack_storage_size = MAX_ENTRIES,
	.perf_max_stack_depth = STACK_DEPTH,
	.verbose = false,
	.command = NULL,
};

const char *argp_program_version = "doublefree 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] = "Detect and report doublefree error.\n"
"\n"
"-c or -p is a mandatory option\n"
"EXAMPLES:\n"
"    doublefree -p 1234             # Detect doublefree on process id 1234\n"
"    doublefree -c a.out            # Detect doublefree on a.out\n"
"    doublefree -c 'a.out arg'      # Detect doublefree on a.out with argument\n";
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "help", 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{ "pid", 'p', "PID", 0, "Detect doublefree on the specified process", 0 },
	{ "command", 'c', "COMMAND", 0, "Execute the command and detect doublefree", 0 },
	{},
};

static struct doublefree_bpf *obj = NULL;
static struct syms *syms = NULL;
static enum log_level log_level = ERROR;

static void __p(FILE *outstream, enum log_level level, char *level_str, char *fmt, ...)
{
	va_list ap;
	char mon[4];
	int day, year, hour, minute, second;

	if (level < log_level)
		return;

	sscanf(__DATE__, "%s %d %d", mon, &day, &year);
	sscanf(__TIME__, "%d:%d:%d", &hour, &minute, &second);

	va_start(ap, fmt);
	fprintf(outstream, DATE_FORMAT, year, mon, day, hour, minute, second);
	fprintf(outstream, "%s ", level_str);
	vfprintf(outstream, fmt, ap);
	fprintf(outstream, "\n");
	va_end(ap);
	fflush(outstream);
}

static void set_log_level(enum log_level level)
{
	log_level = level;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
        exiting = 1;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid <= 0) {
			p_err("Invalid PID: %s", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.command = strdup(arg);
		if (!env.command) {
			p_err("Failed to set command: %s", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static pid_t fork_exec(char *cmd)
{
	int i = 0;
	const char *delim = " ";
	char **argv = NULL;
	char *ptr = NULL;
	char *filepath = NULL;
	pid_t pid = 0;

	if (!cmd) {
		p_err("Invalid command");
		return -1;
	}

	pid = fork();
	if (pid > 0) {
		/* Child process created */
		return pid;
	} else if (pid == 0) {
		/* Child process executes followings */

		/* It is enough to alloc half length of cmd to save argv */
		argv = calloc(sizeof(char *), strlen(cmd) / 2);
		if (!argv) {
			p_err("Failed to allocate memory");
			return -1;
		}

		ptr = strtok(cmd, delim);
		if (!ptr) {
			p_err("Invalid command");
			free(argv);
			return -1;
		}

		filepath = ptr;
		ptr = strtok(NULL, delim);
		argv[i++] = filepath;
		argv[i++] = ptr;
		do {
			ptr = strtok(NULL, delim);
			argv[i++] = ptr;
		} while(ptr);

		execve(filepath, argv, NULL);
		free(argv);
	}

	return -1;
}

static int attach_uprobe(struct probe *probe)
{
	off_t func_off = get_elf_func_offset(probe->lib_path, probe->name);

	if (probe->check && func_off < 0)
		return -1;

	probe->links = bpf_program__attach_uprobe(probe->prog,
						  probe->is_ret,
						  probe->pid,
						  probe->lib_path,
						  func_off);
	if (probe->check && !probe->links) {
		p_err("Failed to attach u[ret]probe %s: %s", probe->name, strerror(errno));
		return -1;
	}

	return 0;
}

static int attach_uprobes(void)
{
	int i = 0;
	int err = 0;
	char libc_path[PATH_MAX] = {};
	struct probe probes[] = {
		URETPROBE_ELEM(malloc, CHECK_FAIL)
		UPROBE_ELEM(free, CHECK_FAIL)
		URETPROBE_ELEM(calloc, CHECK_FAIL)
		UPROBE_ELEMS(realloc, CHECK_FAIL)
		UPROBE_ELEMS(posix_memalign, CHECK_FAIL)
		URETPROBE_ELEM(memalign, CHECK_FAIL)

		URETPROBE_ELEM(aligned_alloc, !CHECK_FAIL)
		URETPROBE_ELEM(valloc, !CHECK_FAIL)
		URETPROBE_ELEM(pvalloc, !CHECK_FAIL)
		UPROBE_ELEMS(reallocarray, !CHECK_FAIL)
	};

	err = get_pid_lib_path(1, "c", libc_path, PATH_MAX);
	if (err) {
		p_err("Failed to find libc.so, err: %d", err);
		return err;
	}

	for (i = 0; i < sizeof(probes) / sizeof(struct probe); ++i) {
		err = attach_uprobe(&probes[i]);
		if (err < 0)
			return err;
	}

	return 0;
}

static void print_backtrace(int stackid) {
	size_t i = 0;
	int err = 0;
	unsigned long *ip = NULL;
	int sfd = bpf_map__fd(obj->maps.stack_traces);
	struct sym_info sinfo = {};

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		p_err("Failed to allocate memory");
		return;
	}

	err = bpf_map_lookup_elem(sfd, &stackid, ip);
	if (err < 0) {
		p_err("Failed to lookup elem on stack map: %s", strerror(errno));
		free(ip);
		return;
	}

	for (i = 0; i < env.perf_max_stack_depth && ip[i]; ++i) {
		printf("\t#%zu %#016lx", i + 1, ip[i]);
		err = syms__map_addr_dso(syms, ip[i], &sinfo);
		if (!err) {
			if (sinfo.sym_name)
				printf(" %s+0x%lx (%s+0x%lx)",
				       sinfo.sym_name, sinfo.sym_offset,
				       sinfo.dso_name, sinfo.dso_offset);
			else
				printf(" [unknown] (%s+0x%lx)",
				       sinfo.dso_name, sinfo.dso_offset);
		}
		printf("\n");
	}
	printf("\n");

	free(ip);
}

static int get_stackid(int fd, unsigned long key) {
	struct doublefree_info_t val = {};
	int err = 0;

	err = bpf_map_lookup_elem(fd, &key, &val);
	if (err < 0) {
		p_err("Failed to get stacktrace info: %s", strerror(errno));
		return err;
	}

	return val.stackid;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event *e = data;
	int stackid = 0;
	int allocs_fd = bpf_map__fd(obj->maps.allocs);
	int deallocs_fd = bpf_map__fd(obj->maps.deallocs);

	if (e->err == -1) {
		p_err("Unexpected error occured");
		return;
	}

	printf("\nAllocation:\n");
	stackid = get_stackid(allocs_fd, e->addr);
	if (stackid >= 0)
		print_backtrace(stackid);

	printf("First deallocation:\n");
	stackid = get_stackid(deallocs_fd, e->addr);
	if (stackid >= 0)
		print_backtrace(stackid);

	printf("Second deallocation:\n");
	print_backtrace(e->stackid);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	p_err("Lost %llu events on CPU #%d!", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	int err = 0;
	struct syms_cache *syms_cache = NULL;
	struct perf_buffer *pb = NULL;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	set_log_level(INFO);

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.verbose)
		set_log_level(DEBUG);

	if (env.command != NULL) {
		if (env.pid != -1) {
			p_err("Use either -c or -p only");
			return -1;
		}
		env.pid = fork_exec(env.command);
		if (env.pid < 0) {
			p_err("Failed to spawn child process");
			return -1;
		}
		p_info("Execute command: %s(pid %d)", env.command, env.pid);
	}

	if (env.pid == -1) {
		p_err("-c or -p is a mandatory option");
		return -1;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = doublefree_bpf__open();
	if (!obj) {
		p_err("Failed to open BPF object");
		return -1;
	}

	bpf_map__set_value_size(obj->maps.stack_traces,
				env.perf_max_stack_depth * sizeof(__u64));
	bpf_map__set_max_entries(obj->maps.stack_traces,
				 env.stack_storage_size);

	err = doublefree_bpf__load(obj);
	if (err) {
		p_err("Failed to load BPF object: %d", err);
		return -1;
	}

	err = attach_uprobes();
	if (err)
		return -1;

	/*
	 * The symbols are pre-set as global variables and used in the event
	 * handler. If a doublefree error occurs, causing the target process to
	 * terminate, it becomes impossible to obtain symbols from the
	 * terminated process.
	 */
	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		p_warn("Failed to load symbol");
	} else {
		syms = syms_cache__get_syms(syms_cache, env.pid);
		if (!syms)
			p_warn("Failed to get symbol");
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		p_err("Failed to open perf buffer: %s", strerror(errno));
		return -1;
	}

        if (signal(SIGINT, sig_int) == SIG_ERR) {
                p_err("Failed to set signal handler: %s", strerror(errno));
		return -1;
        }

	printf("Tracing doublefree... Hit Ctrl-C to stop\n");
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			p_err("Failed to poll perf buffer: %d", err);
			break;
		}
	}

	/* cleanup */
	perf_buffer__free(pb);
	syms_cache__free(syms_cache);
	doublefree_bpf__destroy(obj);
	free(env.command);

	return 0;
}
