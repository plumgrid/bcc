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
#include <pthread.h>
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
#include <sys/types.h>
#include "profile.h"
#include "profile_v1.skel.h"
#include "trace_helpers.h"
#include "log.h"

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */


#define INTERVAL		8
#define START_AFTER		9
#define OUTPUT_DIR		10
#define LOAD_NUM		11


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

// file path size
#define PATH_BYTES_128 128
#define MSG_BYTES_32 32

/* control pthread communication*/
struct pthread_st {
	volatile bool  exit_flag;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	pthread_t timer_thread;
	pthread_t main_thread;
	char *outfile;
	int changes_fd;
	int counts_fd;
	int countsback_fd;
	int stacks_fd;
	int usr_map_fd;
	int stacksback_fd;
	bool changes_v;
	FILE *err_fp;
	FILE *info_fp;
	char cur_info_file_path[PATH_BYTES_128];
} p_st;



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
	int interval;
	int second;
	int startafter;
	char* output_file;
	int load_num;
} env = {
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.duration = INT_MAX,
	.freq = 1,
	.sample_freq = 49,
	.cpu = -1,
	.interval = 150,
	.second = 1,
	.startafter = 5,
	.load_num = 5
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
	{ "interval", INTERVAL, "INTERVAL", 0, "intervals between logs", 0 },
	{ "start-after", START_AFTER, "START-AFTER", 0, "how long to collect data", 0 },
	{ "output-dir", OUTPUT_DIR, "OUTPUT-DIR", 0, "output file dir", 0 },
	{ "load-num", LOAD_NUM, "load-num", 0, "wait to load sysms", 0 },
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
	case INTERVAL:
		env.interval = atoi(arg);
		break;
	case OUTPUT_DIR:
		env.output_file = arg;
		break;
	case START_AFTER:
		env.startafter = atoi(arg);
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
	p_st.exit_flag = true;
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

struct tm *get_current_tm_info() {
	time_t now;
	time(&now);
	struct tm *tm_info;
	tm_info = localtime(&now);
    return tm_info;
}

void transtime(char* des, char* str, char* file_name, char* fm) {
  struct tm * tm_info=get_current_tm_info();
  sprintf(des, "%s/%s.%02d%02d-%02d%02d%02d.%s", 
		str,
		file_name,
    	tm_info->tm_mon + 1,
    	tm_info->tm_mday,
    	tm_info->tm_hour,
    	tm_info->tm_min,
    	tm_info->tm_sec,
		fm);
}

void transtime_bcclog(char* des, char* str) {
  struct tm * tm_info=get_current_tm_info();
  sprintf(des, "%s%02d%02d_%02d_%02d_%02d", 
		str,
    	tm_info->tm_mon + 1,
    	tm_info->tm_mday,
    	tm_info->tm_hour,
    	tm_info->tm_min,
    	tm_info->tm_sec);
}

int init_resource(int stacks_fd, int counts_fd, int countsback_fd, int changes_fd, 
	int usr_map_fd, int stacksback_fd) {
  p_st.exit_flag = false;
  p_st.changes_v = true;
  pthread_mutex_init(&p_st.mutex, NULL);
  pthread_cond_init(&p_st.cond, NULL);
  p_st.stacks_fd = stacks_fd;
  p_st.counts_fd = counts_fd;
  p_st.countsback_fd = countsback_fd;
  p_st.changes_fd = changes_fd;
  p_st.usr_map_fd = usr_map_fd;
  p_st.stacksback_fd = stacksback_fd;
  p_st.err_fp = NULL;
  p_st.info_fp = NULL;

  char filename[PATH_BYTES_128] = {}; 
  transtime(filename, env.output_file ,"glog_err","log");
  set_log_file(filename);
  set_log_level(DEBUG);
  memset(p_st.cur_info_file_path, 0 ,sizeof(p_st.cur_info_file_path));

  LOG_INFO("init resource has completed.");
  return 0;
}

void gzip_file(const char* filepath) {

	// gzip cur path
	char command[PATH_BYTES_128 + MSG_BYTES_32] = {0};
	sprintf(command, "gzip %s", p_st.cur_info_file_path);
	int result = system(command);
    if (result == 0) {
    	LOG_INFO("file gzip success");
    } else {
    	LOG_ERROR("file gzip failed");
    }
}

void destroy_resource() {
  pthread_join(p_st.timer_thread, NULL);
  pthread_mutex_destroy(&p_st.mutex);
  pthread_cond_destroy(&p_st.cond);
  LOG_INFO("thread mutex conditon resource recycle.");
//   fprintf(stderr, "thread mutex conditon resource recycle\n");

  if (p_st.err_fp != NULL) {
	  fclose(p_st.err_fp);
  }
  if (p_st.info_fp != NULL) {
	  fclose(p_st.info_fp);
  }

  struct stat file_stat;
  if (stat(p_st.cur_info_file_path, &file_stat) == 0) {
	gzip_file(p_st.cur_info_file_path);     
  }

}

void* time_process(void *arg) {
  LOG_INFO("begin to time_process");
  sleep(env.startafter);
  if (p_st.exit_flag) {
    pthread_cond_broadcast(&p_st.cond);
	LOG_ERROR("received exit signal, send signals.");
	// fprintf(stderr, "received exit signal, send signals\n");
	return NULL;
  }

  __u32 key = 0;
  if (bpf_map_update_elem(p_st.changes_fd, &key, &p_st.changes_v, BPF_ANY)) {
	LOG_ERROR("Failed bpf_map_update_elem to map");
	p_st.exit_flag = true;
	pthread_cond_broadcast(&p_st.cond);
	return NULL;
  }

  while (true) {
	char msg[PATH_BYTES_128];
	sprintf(msg, "start to sleeping,cur_changes_v:%d", p_st.changes_v);
	LOG_INFO(msg);
    sleep(env.second);
	p_st.changes_v = !p_st.changes_v;
	
	if (bpf_map_update_elem(p_st.changes_fd, &key, &p_st.changes_v, BPF_ANY)) {
		LOG_ERROR("Failed bpf_map_update_elem to map");
		p_st.exit_flag = true;
		pthread_cond_broadcast(&p_st.cond);
		return NULL;
  	}

	memset(msg, 0 ,sizeof(msg));
	sprintf(msg, "sleeping over, cur_changes_v:%d", p_st.changes_v);
	LOG_INFO(msg);


    pthread_cond_broadcast(&p_st.cond);

    if (p_st.exit_flag) {
	  LOG_ERROR("received exit signal, send signals");
      break;
    }
  }
  LOG_WARNING("time function will exit");
  return NULL;
}


int map_exists_item(int counts_map) {
	struct key_t key = {0};
	struct key_t next_key = {};

	int ret = bpf_map_get_next_key(counts_map, &key, &next_key);
	if (ret < 0){
		return 1;
	}
	return 0;
}

int stackmap_exists_item(int stack_map) {
	__u32 key = 0;
	__u32 next_key = 0;

	int ret = bpf_map_get_next_key(stack_map, &key, &next_key);
	if (ret < 0){
		return 1;
	}
	return 0;
}


int clear_counts(int counts_map){

	//clear counts
	struct key_t key = {0};
	struct key_t next_key = {};
	int ret;
	// debug
	int i = 0;

	do {
		ret = bpf_map_get_next_key(counts_map, &key, &next_key);
		if (ret < 0) {
			if (key.pid != 0) {
				// not have next item and delete last item;
				// char msf[PATH_BYTES_128];
				// sprintf(msf,"cur_index:%d, ret: %d",i, ret);
				// LOG_INFO(msf);
				++i;
				bpf_map_delete_elem(counts_map, &key);
			} else {
				LOG_WARNING("this is empty countsmap");
			}
			break;
		} else if (0 == ret && 0 == key.pid) {
			key = next_key;
			continue;
		} else {
			// char msf[PATH_BYTES_128];
			// sprintf(msf,"cur_index:%d, ret: %d",i, ret);
			// LOG_INFO(msf);
			if (bpf_map_delete_elem(counts_map, &key) != 0) {
				return 1;
			}
			key = next_key;
		}
		++i;

	}while (ret == 0);

	char msf[MSG_BYTES_32];
	sprintf(msf,"clear counts:%d",i);
	LOG_INFO(msf);

	return 0;
}


int clear_stacks(int stackmap) {
	//clear counts
	__u32 key = 0;
	__u32 next_key;

	int ret;
	// debug
	int i = 0;

	do {
		ret = bpf_map_get_next_key(stackmap, &key, &next_key);
		if (ret < 0) {
			if (key != 0) {
				++i;
				bpf_map_delete_elem(stackmap, &key);
			} else {
				LOG_WARNING("this is empty stackmap");
			}
			break;
		} else if (0 == ret && 0 == key) {
			key = next_key;
			continue;
		} else {
			// char msf[PATH_BYTES_128];
			// sprintf(msf,"cur_index:%d, ret: %d",i, ret);
			// LOG_INFO(msf);
			if (bpf_map_delete_elem(stackmap, &key) != 0) {
				return 1;
			}
			key = next_key;
		}
		++i;

	}while (ret == 0);

	char msf[MSG_BYTES_32];
	sprintf(msf,"clear stacks:%d",i);
	LOG_INFO(msf);

	return 0;
}



int clone_counts(int counts_map, int usr_map, int* counts) {

	struct key_t key, next_key;
	__u64 value;
	// debug
	int i = 0;

	while (true) {
		int ret = bpf_map_get_next_key(counts_map, &key, &next_key);
		if (ret < 0) {
			break;
    	}
		// 查找当前键对应的值
    	ret = bpf_map_lookup_elem(counts_map, &next_key, &value);
		if (ret < 0) {
			LOG_ERROR("Failed to lookup map element");
        	return 1;
    	}
		// 将键值对插入到用户空间映射中
    	ret = bpf_map_update_elem(usr_map, &next_key, &value, BPF_ANY);
		if (ret < 0) {
			LOG_ERROR("Failed to update user space map");
        	return 1;
    	}
		key = next_key;
		++i;
	}

	char msf[MSG_BYTES_32];
	sprintf(msf,"clone_counts:%d",i);
	LOG_INFO(msf);
	*counts = i;
	return 0;
}

void main_process() {
  static int i = 0;

  while (true) {
	char msf[MSG_BYTES_32];
	sprintf(msf,"index:%d",i);
	LOG_INFO(msf);

    pthread_mutex_lock(&p_st.mutex);
    int ret_pt = pthread_cond_wait(&p_st.cond, &p_st.mutex);
	pthread_mutex_unlock(&p_st.mutex);

	if (p_st.exit_flag) {
      break;
    }

    if ( ret_pt == EINTR ) {
	  LOG_WARNING("main thread interrped!!");
    } else {
	  LOG_WARNING("main thread wakeuped!!");
    }

	// choose file
	if (i % env.interval == 0) {
	
		if (NULL != p_st.info_fp) {
			fclose(p_st.info_fp);
			gzip_file(p_st.cur_info_file_path);
		}

		memset(p_st.cur_info_file_path, 0, sizeof(p_st.cur_info_file_path));
		transtime(p_st.cur_info_file_path, env.output_file, "bcc_profile", "log");
		p_st.info_fp = freopen(p_st.cur_info_file_path, "a+", stdout);
	}

	char bcc_profile_stamp[PATH_BYTES_128];
	memset(bcc_profile_stamp, 0, sizeof(bcc_profile_stamp));
	char bcc_profile[] = "bcc_profile : ";
	transtime_bcclog(bcc_profile_stamp, bcc_profile);
	fprintf(p_st.info_fp, "%s\n", bcc_profile_stamp);

	// choose map
    if(!p_st.changes_v) {
		LOG_INFO("choose counts map and stacks");
		if (map_exists_item(p_st.counts_fd) == 0 && stackmap_exists_item(p_st.stacks_fd) == 0) {
			LOG_INFO("counts map exits data");
			print_counts(p_st.counts_fd,p_st.stacks_fd);

			LOG_INFO("clear_counts:p_st.counts_fd.");
			int ret_clear = clear_counts(p_st.counts_fd);
			if (0 != ret_clear) {
				LOG_ERROR("counts_fd clear falied");
				break;
			}

			LOG_INFO("clear_stack:p_st.stack_fd.");
			ret_clear = clear_stacks(p_st.stacks_fd);
			if (0 != ret_clear) {
				LOG_ERROR("stacks_fd clear falied");
				break;
			}
		}

	} else {
		LOG_INFO("choose countsback map and stacksback");
		if (map_exists_item(p_st.countsback_fd) == 0 && stackmap_exists_item(p_st.stacksback_fd) == 0) {
			LOG_INFO("countsback map exits data");
			print_counts(p_st.countsback_fd,p_st.stacksback_fd);

			LOG_INFO("clear_counts:p_st.countsback_fd.");
			int ret_clear = clear_counts(p_st.countsback_fd);
			if (0 != ret_clear) {
				LOG_ERROR("countsback_fd clear falied");
				break;
			}

			LOG_INFO("clear_stackback:p_st.stacksback_fd.");
			ret_clear = clear_stacks(p_st.stacksback_fd);
			if (0 != ret_clear) {
				LOG_ERROR("stacksback_fd clear falied");
				break;
			}	
		}
	}
	++i;
  }

  p_st.exit_flag = true;
  LOG_WARNING("main thread set p_st.exit_flag = true");
  LOG_WARNING("main_function work over");
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_link *links[MAX_CPU_NR] = {};
	struct profile_v1_bpf *obj;
	int pids_fd, tids_fd;
	int err, i;
	__u8 val = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.user_stacks_only && env.kernel_stacks_only) {
		LOG_ERROR("user_stacks_only and kernel_stacks_only cannot be used together.");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		LOG_ERROR("failed to get # of possible cpus.");
		// printf("failed to get # of possible cpus: '%s'!\n",
		//        strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		LOG_ERROR("the number of cpu cores is too big, please increase MAX_CPU_NR's value and recompile.");
		return 1;
	}

	obj = profile_v1_bpf__open();
	if (!obj) {
		LOG_ERROR("failed to open BPF object");
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


	bpf_map__set_value_size(obj->maps.stackmapback,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmapback, env.stack_storage_size);


	err = profile_v1_bpf__load(obj);
	if (err) {
		LOG_ERROR("failed to load BPF programs");
		goto cleanup;
	}

	if (env.pids[0]) {
		pids_fd = bpf_map__fd(obj->maps.pids);
		for (i = 0; i < MAX_PID_NR && env.pids[i]; i++) {
			if (bpf_map_update_elem(pids_fd, &(env.pids[i]), &val, BPF_ANY) != 0) {
				LOG_ERROR("failed to init pids map");
				// fprintf(stderr, "failed to init pids map: %s\n", strerror(errno));
				goto cleanup;
			}
		}
	}
	else if (env.tids[0]) {
		tids_fd = bpf_map__fd(obj->maps.tids);
		for (i = 0; i < MAX_TID_NR && env.tids[i]; i++) {
			if (bpf_map_update_elem(tids_fd, &(env.tids[i]), &val, BPF_ANY) != 0) {
				LOG_ERROR("failed to init tids map");
				// fprintf(stderr, "failed to init tids map: %s\n", strerror(errno));
				goto cleanup;
			}
		}
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		LOG_ERROR("failed to load kallsyms");
		// fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		LOG_ERROR("failed to create syms_cache");
		// fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}

	err = open_and_attach_perf_event(obj->progs.do_perf_event, links);
	if (err)
		goto cleanup;

	signal(SIGINT, sig_handler);

	if (!env.folded)
		print_headers();
	
	// char user_space_map_name[] = "user_space_map";

	// int user_space_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, 
	// 						user_space_map_name,
	// 						sizeof(struct key_t), 
	// 						sizeof(__u64), 
	// 						MAX_ENTRIES, 
	// 						0);
		
	// if (user_space_map_fd < 0) {
	// 	LOG_ERROR("Failed to create user space map");
    // 	// fprintf(stderr, "Failed to create user space map\n");
    // 	goto cleanup;
	// }

	/*
	 * We'll get sleep interrupted when someone presses Ctrl-C.
	 * (which will be "handled" with noop by sig_handler)
	 */
	// sleep(env.duration);

	// print_counts(bpf_map__fd(obj->maps.counts),
	// 	     bpf_map__fd(obj->maps.stackmap));
	// kill -2 to process pid to exir

	int res = init_resource(bpf_map__fd(obj->maps.stackmap),
		bpf_map__fd(obj->maps.counts),
		bpf_map__fd(obj->maps.countsback),
		bpf_map__fd(obj->maps.changes),
		bpf_map__fd(obj->maps.countsusers),
		bpf_map__fd(obj->maps.stackmapback));

	if (res != 0) {
		goto cleanup;
	}

	LOG_INFO("create init_resource success");
	// char msg[PATH_BYTES_128];
	// sprintf(msg, "stacks:%d, count:%d, countsback:%d, changes:%d, user_map_fd:%d",
	// 				p_st.stacks_fd,
	// 				p_st.counts_fd,
	// 				p_st.countsback_fd,
	// 				p_st.changes_fd,
	// 				p_st.usr_map_fd);
	// LOG_INFO(msg);
	//printf("%d,%s,%d,%d-------\n",env.interval,env.output_file,env.startafter,env.stack_storage_size);

	pthread_create(&p_st.timer_thread, NULL, time_process, NULL);

	main_process();

	destroy_resource();

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
	profile_v1_bpf__destroy(obj);

	return err != 0;
}

/* how to excute
* sudo ./profile_v1 --output-dir ~/future/bcc/libbpf-tools/ -f -F 199 --interval 150 --start-after 1  --stack-storage-size 4096  --load-num 10 -p 14927,15003 
*/

/* how to parse
*  python ./parse_results.py --dir /home/mi/future/bcc/libbpf-tools
*  bash generate_svg.sh /home/mi/future/bcc/libbpf-tools
*/