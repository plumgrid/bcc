/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright 2022 LG Electronics Inc. */

// 19-Jul-2022 Bojun Seo Created this.
#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "alsan.h"
#include "alsan.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"
#include "c-vector/cvector.h"
#include "uthash/src/uthash.h"

#define ALSAN_OPTIMIZED
#define STACK_DEPTH 127
#define WORD_SIZE (sizeof(void*))
#define CHECK_FAIL true
#define DEFAULT_SUPPR_PATH "/usr/etc/suppr.txt"
#define DEFAULT_INTERVAL 10
#define DATE_FORMAT "%1d-%s-%02d %02d:%02d:%02d "

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

#define p_debug(fmt, ...) __p(stderr, DEBUG, "DEBUG", fmt, ##__VA_ARGS__)
#define p_info(fmt, ...) __p(stderr, INFO, "INFO", fmt, ##__VA_ARGS__)
#define p_warn(fmt, ...) __p(stderr, WARN, "WARN", fmt, ##__VA_ARGS__)
#define p_err(fmt, ...) __p(stderr, ERROR, "ERROR", fmt, ##__VA_ARGS__)

#define ON_MEM_FAILURE(buf) \
	do { \
		if (NULL == buf) { \
			p_err("FATAL: Failed to allocate memory on %s", __func__); \
			exit(-1); \
		} \
	} while (false)

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

/* Used to parse /proc/pid/maps file */
enum maps {
	MAPS_ADDRESS = 0,
	MAPS_PERMISSIONS = 1,
	MAPS_OFFSET = 2,
	MAPS_DEVICE = 3,
	MAPS_INODE = 4,
	MAPS_PATH = 5,
	MAPS_COLUMN_MAX = 6
};

static struct env {
	pid_t pid;
	int stack_storage_size;
	int perf_max_stack_depth;
	int interval; /* unit: second */
	int top;
	bool verbose;
	bool stop_the_world;
	char *command;
	char *suppr;
} env = {
	.pid = -1,
	.stack_storage_size = MAX_ENTRIES,
	.perf_max_stack_depth = STACK_DEPTH,
	.interval = DEFAULT_INTERVAL,
	.top = -1,
	.verbose = false,
	.stop_the_world = false,
	.command = NULL,
	.suppr = DEFAULT_SUPPR_PATH,
};

/*
 * The three structs below are designed for use in uthash library. The field
 * name for the key must be 'id' to use uthash library. `hh` is used as handle
 * inside uthash library, but it should be defined inside the struct. The
 * remaining fields are the values for the uthash map. For more details:
 * https://github.com/troydhanson/uthash
 */

/*
 * key: address
 * value: size, stack_id, tag
 */
struct alsan_info_ext_t {
	__u64 size;
	int stack_id;
	enum chunk_tag tag;
	__u64 id;
	UT_hash_handle hh;
};

/*
 * key: stack_id
 * value: size, count
 */
struct report_info_t {
	__u64 size;
	int count;
	int id;
	UT_hash_handle hh;
};

/*
 * key: begin
 * value: end, is_heap
 */
struct root_region_t {
	__u64 end;
	bool is_heap;
	__u64 id;
	UT_hash_handle hh;
};

typedef void (*for_each_chunk_callback)(__u64 chunk);

const char *argp_program_version = "alsan 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] = "Detect memory leak resulting from unreachable pointers.\n"
"\n"
"Either -c or -p is a mandatory option\n"
"EXAMPLES:\n"
"    alsan -p 1234             # Detect leaks on process id 1234\n"
"    alsan -c a.out            # Detect leaks on a.out\n"
"    alsan -c 'a.out arg'      # Detect leaks on a.out with argument\n";
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "help", 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{ "pid", 'p', "PID", 0, "Detect memory leak on the specified process", 0 },
	{ "stop-the-world", 'w', NULL, 0, "Stop the target process during tracing", 0 },
	{ "command", 'c', "COMMAND", 0, "Execute and detect memory leak on the specified command", 0 },
	{ "interval", 'i', "INTERVAL", 0, "Set interval in second to detect leak", 0 },
	{ "top", 'T', "TOP", 0, "Report only specified amount of backtraces", 0 },
	{ "suppressions", 's', "SUPPRESSIONS", 0, "Suppressions file name", 0 },
	{},
};

const char *rw_permission = "rw";
const char *heap_str = "[heap]";
const char *stack_str = "[stack]";

struct alsan_bpf *obj = NULL;
FILE *fp_mem = NULL;
static enum log_level log_level = ERROR;

cvector_vector_type(__u64) frontier = NULL;
cvector_vector_type(__u64) key_table = NULL;
cvector_vector_type(pid_t) tids = NULL;
cvector_vector_type(char*) suppression = NULL;

struct alsan_info_ext_t *allocs = NULL;
struct report_info_t *direct = NULL;
struct report_info_t *indirect = NULL;
struct root_region_t *certain = NULL;
struct root_region_t *uncertain = NULL;

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


static int get_tids(pid_t pid, int *tids, size_t len)
{
	int nr_tid = 0;
	char path[PATH_MAX];
	struct dirent *ent;
	DIR *dp;

	snprintf(path, sizeof(path), "/proc/%d/task", pid);

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((ent = readdir(dp)) != NULL) {
		if (nr_tid >= len)
			return -ENOMEM;

		if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
			continue;

		tids[nr_tid++] = strtol(ent->d_name, NULL, 10);
	}

	closedir(dp);

	return nr_tid;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
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
	case 'w':
		env.stop_the_world = true;
		break;
	case 'c':
		env.command = strdup(arg);
		if (!env.command) {
			p_err("Failed to set command: %s", arg);
			argp_usage(state);
		}
		break;
	case 'i':
		errno = 0;
		env.interval = strtol(arg, NULL, 10);
		if (errno || env.interval <= 0) {
			p_err("Invalid interval: %s", arg);
			argp_usage(state);
		}
		break;
	case 'T':
		errno = 0;
		env.top = strtol(arg, NULL, 10);
		if (errno || env.top <= 0) {
			p_err("Invalid top: %s", arg);
			argp_usage(state);
		}
		break;
	case 's':
		env.suppr = strdup(arg);
		ON_MEM_FAILURE(env.suppr);
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
		UPROBE_ELEMS(malloc, CHECK_FAIL)
		UPROBE_ELEM(free, CHECK_FAIL)
		UPROBE_ELEMS(calloc, CHECK_FAIL)
		UPROBE_ELEMS(realloc, CHECK_FAIL)
		UPROBE_ELEMS(posix_memalign, CHECK_FAIL)
		UPROBE_ELEMS(memalign, CHECK_FAIL)

		UPROBE_ELEMS(aligned_alloc, !CHECK_FAIL)
		UPROBE_ELEMS(valloc, !CHECK_FAIL)
		UPROBE_ELEMS(pvalloc, !CHECK_FAIL)
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

static void for_each_chunk(for_each_chunk_callback callback)
{
	struct alsan_info_ext_t *curr = NULL;
	struct alsan_info_ext_t *next = NULL;

	HASH_ITER(hh, allocs, curr, next) {
		callback(curr->id);
	}
}

static __u64 dereference(__u64 pp)
{
	__u64 val = 0;
	size_t sz = 0;

	fseek(fp_mem, pp, SEEK_SET);
	sz = fread(&val, sizeof(char), WORD_SIZE, fp_mem);
	if (WORD_SIZE != sz && kill(env.pid, 0) != 0) {
		p_warn("Cannot access to the target process, pid: %d", env.pid);
		exit(0);
	}

	return val;
}

static __u64 search_key_in_key_table(__u64 start, __u64 end, __u64 ptr)
{
	struct alsan_info_ext_t *val = NULL;
	__u64 key = 0;
	__u64 mid = 0;

	while (1) {
		if (start >= end)
			return 0;

		if (end - start == 1) {
			key = key_table[start];
			HASH_FIND(hh, allocs, &key, sizeof(__u64), val);
			if (key <= ptr && ptr < key + val->size)
				return key;

			return 0;
		}

		mid = (start + end) / 2;

		if (ptr < key_table[mid])
			end = mid;
		else
			start = mid;
	}
}

static __u64 points_into_chunk(__u64 ptr)
{
#ifndef ALSAN_OPTIMIZED
	struct alsan_info_ext_t *curr = NULL;
	struct alsan_info_ext_t *next = NULL;

	HASH_ITER(hh, allocs, curr, next) {
		if (curr->id <= ptr && ptr < curr->id + curr->size)
			return curr->id;
	}

	return 0;
#else
	return search_key_in_key_table(0, cvector_size(key_table), ptr);
#endif
}

static void scan_range_for_pointers(__u64 begin, __u64 end, enum chunk_tag tag)
{
	int alignment = WORD_SIZE; /* Alignment in bytes */
	__u64 pp = begin;
	__u64 p = 0;
	__u64 chunk = 0;
	struct alsan_info_ext_t *val = NULL;

	if (pp % alignment != 0) {
		pp = pp + alignment - pp % alignment;
	}

	while (pp + WORD_SIZE <= end) {
		p = dereference(pp);
		pp += alignment;

		chunk = points_into_chunk(p);
		if (!chunk)
			continue;

		if (chunk == begin)
			continue;

		HASH_FIND(hh, allocs, &chunk, sizeof(__u64), val);
		if (!val)
			continue;

		if (val->tag == REACHABLE || val->tag == IGNORED)
			continue;

		val->tag = tag;
		if (tag == REACHABLE)
			cvector_push_back(frontier, p);

	}
}

static void update_report_info(struct report_info_t **hash,
			       struct alsan_info_ext_t *val)
{
	struct report_info_t *old = NULL;
	struct report_info_t *item = NULL;
	int stack_id = val->stack_id;

	HASH_FIND(hh, *hash, &stack_id, sizeof(int), old);
	if (!old) {
		item = (struct report_info_t*)malloc(sizeof(struct report_info_t));
		ON_MEM_FAILURE(item);
		item->size = val->size;
		item->id = val->stack_id;
		item->count = 1;
		HASH_ADD(hh, *hash, id, sizeof(int), item);
	} else {
		++old->count;
	}
}

static void collect_leaks_cb(__u64 chunk)
{
	struct alsan_info_ext_t *val = NULL;

	chunk = points_into_chunk(chunk);
	if (!chunk)
		return;

	HASH_FIND(hh, allocs, &chunk, sizeof(__u64), val);
	if (!val)
		return;

	if (val->tag == DIRECTLY_LEAKED)
		update_report_info(&direct, val);
	else if (val->tag == INDIRECTLY_LEAKED)
		update_report_info(&indirect, val);
}

static void mark_indirectly_leaked_cb(__u64 chunk)
{
	struct alsan_info_ext_t *val = NULL;

	chunk = points_into_chunk(chunk);
	if (!chunk)
		return;

	HASH_FIND(hh, allocs, &chunk, sizeof(__u64), val);
	if (!val)
		return;

	if (val->tag != REACHABLE)
		scan_range_for_pointers(val->id, val->id + val->size,
					INDIRECTLY_LEAKED);
}

int compare(const void *a, const void *b)
{
	__u64 aa = *(__u64*)a;
	__u64 bb = *(__u64*)b;

	if (aa < bb)
		return -1;

	if (aa > bb)
		return 1;

	return 0;
}

static int read_table(void)
{
	struct alsan_info_t val = {};
	struct root_region_t *curr = NULL;
	struct root_region_t *next = NULL;
	struct alsan_info_ext_t *item = NULL;
	unsigned long lookup_key = 0;
	unsigned long address = 0;
	int err = 0;
	int afd = bpf_map__fd(obj->maps.allocs);

	lookup_key = -1;
	while (!bpf_map_get_next_key(afd, &lookup_key, &address)) {
		err = bpf_map_lookup_elem(afd, &address, &val);
		if (err < 0)
			return err;

		item = (struct alsan_info_ext_t*)malloc(sizeof(struct alsan_info_ext_t));
		ON_MEM_FAILURE(item);

		item->size = val.size;
		item->stack_id = val.stack_id;
		item->tag = val.tag;
		item->id = address;
		HASH_ADD(hh, allocs, id, sizeof(__u64), item);
		cvector_push_back(key_table, address);

		HASH_ITER(hh, uncertain, curr, next) {
			if (curr->id <= address && address < curr->end) {
				curr->is_heap = true;
				break;
			}
		}
		lookup_key = address;
	}
	qsort(key_table, cvector_size(key_table), sizeof(__u64), compare);

	return 0;
}

static bool is_uncertain(char *map_str)
{
	/* if path name does not exist */
	if (!strlen(map_str))
		return true;

	/* Usually map_str value is "\n" if path name does not exist */
	return !strncmp("\n", map_str, strlen("\n"));
}

static bool is_certain(char *map_str)
{
	/* if path name does not exist */
	if (!strlen(map_str))
		return false;

	/* Not including '[' starting path except "[stack]" */
	bool is_heap = !strncmp(heap_str, map_str, strlen(heap_str));
	bool is_sqr_start = ('[' == map_str[0]);
	bool is_stack = !strncmp(stack_str, map_str, strlen(stack_str));

	return !is_heap && (!is_sqr_start || is_stack);
}

static void save_roots(void)
{
	char file_name[FILENAME_MAX] = {};
	char line[LINE_MAX] = {};
	FILE *fp = NULL;
	char *v[MAPS_COLUMN_MAX] = {};
	int i = 0;
	char *ptr = NULL;
	__u64 begin = 0;
	__u64 end = 0;
	const int hex = 16;
	struct root_region_t *item = NULL;
	struct root_region_t *val = NULL;

	snprintf(file_name, sizeof(file_name), "/proc/%d/maps", env.pid);
	fp = fopen(file_name, "rt");
	if (!fp) {
		p_err("Failed to open : %s", file_name);
		return;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		i = 0;
		ptr = strtok(line, " ");
		while (ptr != NULL) {
			v[i] = strdup(ptr);
			ON_MEM_FAILURE(v[i]);

			++i;
			ptr = strtok(NULL, " ");
		}

		/* root should have rw permission */
		if (strncmp(rw_permission, v[MAPS_PERMISSIONS], strlen(rw_permission)))
			goto release;

		ptr = strtok(v[MAPS_ADDRESS], "-");
		begin = strtoull(ptr, NULL, hex);
		ptr = strtok(NULL, "-");
		end = strtoull(ptr, NULL, hex);
		item = (struct root_region_t*)malloc(sizeof(struct root_region_t));
		ON_MEM_FAILURE(item);

		item->end = end;
		item->id = begin;
		item->is_heap = false;

		if (is_uncertain(v[MAPS_PATH]))
			HASH_REPLACE(hh, uncertain, id, sizeof(__u64), item, val);
		else if (is_certain(v[MAPS_PATH]))
			HASH_REPLACE(hh, certain, id, sizeof(__u64), item, val);

		free(val);

release:
		for (i = 0; i < MAPS_COLUMN_MAX; ++i)
			free(v[i]);

	}

	fclose(fp);
}

static void process_roots(struct root_region_t *roots) {
	struct root_region_t *curr = NULL;
	struct root_region_t *next = NULL;

	HASH_ITER(hh, roots, curr, next) {
		if (!(curr->is_heap)) {
			p_debug("root: %lx - %lx", curr->id, curr->end);
			scan_range_for_pointers(curr->id, curr->end, REACHABLE);
		}
	}
}

static void flood_fill_tag(enum chunk_tag tag)
{
	struct alsan_info_ext_t *val = NULL;
	__u64 next_chunk = 0;
	__u64 origin = 0;

	while (!cvector_empty(frontier)) {
		next_chunk = frontier[cvector_size(frontier) - 1];
		cvector_pop_back(frontier);
		origin = points_into_chunk(next_chunk);
		HASH_FIND(hh, allocs, &origin, sizeof(__u64), val);
		if (!val)
			continue;

		scan_range_for_pointers(origin, origin + val->size, tag);
	}
}

/*
 * stop-the-world feature can be used on other architecture(e.g. x86_64)
 * after this register handling code is implemented
 */
static void process_registers(void)
{
#ifdef __aarch64__
	struct user_regs_struct regs;
	struct iovec io;
	long ret = 0;
	int i = 0;
	int j = 0;

	/* Stop the world is a mandatory option to read registers */
	if (!env.stop_the_world)
		return;

	for (i = 0; i < cvector_size(tids); ++i) {
		io.iov_base = &regs;
		io.iov_len = sizeof(regs);
		ret = ptrace(PTRACE_GETREGSET, tids[i], (void*)NT_PRSTATUS,
			     (void*)&io);
		if (ret == -1) {
			p_warn("ptrace failed to get regset from tid: %d, reason: %s",
			       tids[i], strerror(errno));
			continue;
		}
		/*
		 * aarch64 user_regs_struct definition
		 * struct user_regs_struct
		 * {
		 *   unsigned long long regs[31];
		 *   unsigned long long sp;
		 *   unsigned long long pc;
		 *   unsigned long long pstate;
		 * };
		 */
		for (j = 0; j < 31; ++j) {
			p_debug("root: %lx - %lx", regs.regs[j],
				regs.regs[j] + WORD_SIZE);
			scan_range_for_pointers(regs.regs[j],
						regs.regs[j] + WORD_SIZE,
						REACHABLE);
		}
	}
#endif
}

static void classify_all_chunks(void)
{
	process_roots(certain);
	process_roots(uncertain);
	flood_fill_tag(REACHABLE);
	process_registers();
	flood_fill_tag(REACHABLE);
	for_each_chunk(mark_indirectly_leaked_cb);
}

/* Decending order */
static int report_info_sort(struct report_info_t *a, struct report_info_t *b)
{
	return b->size * b->count - a->size * a->count;
}

static void print_report(struct report_info_t *curr, unsigned long *ip,
			 const struct syms *syms, const char *kind)
{
	char report_buf[LINE_MAX * STACK_DEPTH] = {};
	char str[LINE_MAX] = {};
	size_t i = 0;
	size_t j = 0;
	int err;
	struct sym_info sinfo = {};

	snprintf(report_buf, sizeof(report_buf),
		"%lld bytes %s leak found in %d allocations from stack id(%d)\n",
		curr->size * curr->count, kind, curr->count, curr->id);
	for (i = 0; i < env.perf_max_stack_depth && ip[i]; ++i) {
		snprintf(str, sizeof(str), "\t#%ld %#016lx", i+1, ip[i]);
		strcat(report_buf, str);
		err = syms__map_addr_dso(syms, ip[i], &sinfo);
		if (!err) {
			if (sinfo.sym_name)
				snprintf(str, sizeof(str), " %s+0x%lx (%s+0x%lx)",
				       sinfo.sym_name, sinfo.sym_offset,
				       sinfo.dso_name, sinfo.dso_offset);
			else
				snprintf(str, sizeof(str), " [unknown] (%s+0x%lx)",
				       sinfo.dso_name, sinfo.dso_offset);

			strcat(report_buf, str);
		}
		strcat(report_buf, "\n");

		if (i == 0 || i == 1) {
			for (j = 0; j < cvector_size(suppression); ++j) {
				if (strstr(report_buf, suppression[j]) != NULL)
					return;
			}
		}
	}
	printf("%s\n", report_buf);
}

static void report_leaks(struct syms_cache *syms_cache)
{
	struct report_info_t *curr = NULL;
	struct report_info_t *next = NULL;
	const struct syms *syms = NULL;
	int rst = 0;
	int count = 0;
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	int sfd = 0;
	unsigned long *ip = calloc(env.perf_max_stack_depth, sizeof(*ip));

	ON_MEM_FAILURE(ip);

	printf("\n[%04d-%02d-%02d %02d:%02d:%02d] Print leaks:\n",
		tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
	sfd = bpf_map__fd(obj->maps.stack_traces);

	/* Report direct */
	HASH_SORT(direct, report_info_sort);
	HASH_ITER(hh, direct, curr, next) {
		if (count == env.top)
			break;

		++count;
		if (curr->id < 0) {
			printf("%lld bytes direct leak found in %d allocations from unknown stack\n\n",
				curr->size * curr->count, curr->count);
			continue;
		}
		rst = bpf_map_lookup_elem(sfd, &(curr->id), ip);
		syms = syms_cache__get_syms(syms_cache, env.pid);
		if (rst == 0 && syms != NULL)
			print_report(curr, ip, syms, "direct");
	}

	/* Report indirect */
	curr = NULL;
	next = NULL;
	HASH_SORT(indirect, report_info_sort);
	HASH_ITER(hh, indirect, curr, next) {
		if (count == env.top)
			break;

		++count;
		if (curr->id < 0) {
			printf("%lld bytes indirect leak found in %d allocations from unknown stack\n\n",
				curr->size * curr->count, curr->count);
			continue;
		}
		rst = bpf_map_lookup_elem(sfd, &(curr->id), ip);
		syms = syms_cache__get_syms(syms_cache, env.pid);
		if (rst == 0 && syms != NULL)
			print_report(curr, ip, syms, "indirect");
	}
	free(ip);
}

static void delete_hash_alsan_hash(struct alsan_info_ext_t *hash) {
	struct alsan_info_ext_t *curr = NULL;
	struct alsan_info_ext_t *next = NULL;

	HASH_ITER(hh, hash, curr, next) {
		HASH_DEL(hash, curr);
		free(curr);
	}
}

static void delete_hash_report_info(struct report_info_t *hash) {
	struct report_info_t *curr = NULL;
	struct report_info_t *next = NULL;

	HASH_ITER(hh, hash, curr, next) {
		HASH_DEL(hash, curr);
		free(curr);
	}
}

static void delete_hash_root_region(struct root_region_t *hash) {
	struct root_region_t *curr = NULL;
	struct root_region_t *next = NULL;

	HASH_ITER(hh, hash, curr, next) {
		HASH_DEL(hash, curr);
		free(curr);
	}
}

static void empty_table(void)
{
	cvector_free(frontier);
	cvector_free(key_table);
	cvector_free(tids);
	delete_hash_alsan_hash(allocs);
	delete_hash_report_info(direct);
	delete_hash_report_info(indirect);
	delete_hash_root_region(certain);
	delete_hash_root_region(uncertain);
	frontier = NULL;
	key_table = NULL;
	tids = NULL;
	allocs = NULL;
	direct = NULL;
	indirect = NULL;
	certain = NULL;
	uncertain = NULL;
}

static void for_each_tid_ptrace(enum __ptrace_request request)
{
	int i = 0;
	long ret = 0;

	for (i = 0; i < cvector_size(tids); ++i) {
		ret = ptrace(request, tids[i], NULL, NULL);
		if (ret != -1)
			continue;

		p_warn("ptrace failed to request %d, reason: %s",
		       request, strerror(errno));
		p_warn("May failed to stop tid: %d, could cause false alarms",
		       tids[i]);
	}
}

static void for_each_tid_waitpid(void)
{
	int i = 0;
	int status = 0;
	pid_t ret = 0;

	for (i = 0; i < cvector_size(tids); ++i) {
		ret = waitpid(tids[i], &status, __WALL);
		if (ret != -1)
			continue;

		p_warn("waitpid failed, reason: %s", strerror(errno));
		p_warn("May failed to stop tid: %d, could cause false alarms",
		       tids[i]);
	}
}

static void stop_the_world(void) {
	int len = 0;

	if (!env.stop_the_world)
		return;

	cvector_reserve(tids, MAX_THREAD_NUM);
	len = get_tids(env.pid, cvector_begin(tids), MAX_THREAD_NUM);
	cvector_set_size(tids, len);

	for_each_tid_ptrace(PTRACE_SEIZE);
	for_each_tid_ptrace(PTRACE_INTERRUPT);
	for_each_tid_waitpid();
}

static void resume_the_world(void) {
	if (!env.stop_the_world)
		return;

	for_each_tid_ptrace(PTRACE_DETACH);
}

static int do_leak_check(struct syms_cache *syms_cache)
{
	int ret = 0;

	stop_the_world();

	save_roots();
	ret = read_table();
	if (ret < 0) {
		p_warn("Failed to read_table, retry after %d seconds",
		       env.interval);
		resume_the_world();
		return 0;
	}
	classify_all_chunks();
	for_each_chunk(collect_leaks_cb);

	resume_the_world();
	report_leaks(syms_cache);

	return 0;
}

int main(int argc, char **argv)
{
	struct syms_cache *syms_cache = NULL;
	int err = 0;
	char path[PATH_MAX] = {};
	FILE *fp_suppression = NULL;
	char line[LINE_MAX] = {};
	int i = 0;
	char *ptr = NULL;
	char *str = NULL;
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

	if (env.command) {
		env.pid = fork_exec(env.command);
		if (env.pid > 0)
			p_info("execute command: %s(pid %d)", env.command, env.pid);
	}

	if (env.pid == -1) {
		p_err("Either -c or -p is a mandatory option");
		return -1;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = alsan_bpf__open();
	if (!obj) {
		p_err("Failed to open BPF object");
		return -1;
	}

	bpf_map__set_value_size(obj->maps.stack_traces,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stack_traces,
				 env.stack_storage_size);

	err = alsan_bpf__load(obj);
	if (err) {
		p_err("Failed to load BPF object: %d", err);
		return -1;
	}

	err = attach_uprobes();
	if (err) {
		p_err("Failed to attach BPF programs");
		p_err("Is this process alive? pid: %d", env.pid);
		return -1;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		p_err("Failed to load syms");
		return -1;
	}

	snprintf(path, sizeof(path), "/proc/%d/mem", env.pid);
	fp_mem = fopen(path, "rb");
	if (!fp_mem) {
		p_err("Failed to open: %s", path);
		return -1;
	}

	fp_suppression = fopen(env.suppr, "rt");
	if (!fp_suppression) {
		if (strncmp(env.suppr, DEFAULT_SUPPR_PATH, sizeof(DEFAULT_SUPPR_PATH)))
			p_warn("Failed to open: %s", env.suppr);
	} else {
		while (fgets(line, sizeof(line), fp_suppression)) {
			/* suppression line format "kind:string" */
			/* suppression line example1 "leak:/usr/lib/libglib.so" */
			/* suppression line example2 "leak:_dl_init" */
			i = 0;
			ptr = strtok(line, ":");
			if (strcmp("leak", ptr))
				continue;

			ptr = strtok(NULL, ":");
			str = strdup(ptr);
			ON_MEM_FAILURE(str);
			ptr = strchr(str, '\n');
			if (ptr)
				*ptr = '\0';

			cvector_push_back(suppression, str);
		}
	}

	do {
		sleep(env.interval);
		if (kill(env.pid, 0)) {
			p_warn("Cannot access to the target process, pid: %d", env.pid);
			exit(0);
		}
		empty_table();
	} while (!do_leak_check(syms_cache));

	/* cleanup */
	for (i = 0; i < cvector_size(suppression); ++i)
		free(suppression[i]);

	cvector_free(suppression);
	suppression = NULL;
	fclose(fp_mem);
	syms_cache__free(syms_cache);
	alsan_bpf__destroy(obj);
	empty_table();
	free(env.command);
	free(env.suppr);

	return 0;
}
