/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * tcptop: Summarize the top active TCP sessions - like top, but for TCP
 * Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
 *
 * Based on tcptop(8) from BCC by Brendan Gregg.
 * 03-Mar-2022   Francis Laniel   Created this.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcptop.h"
#include "tcptop.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

#define IPV4 0
#define PORT_LENGTH 5

enum SORT {
	ALL,
	SENT,
	RECEIVED,
};

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = -1;
static char *cgroup_path;
static bool cgroup_filtering = false;
static bool clear_screen = true;
static bool no_summary = false;
static bool ipv4_only = false;
static bool ipv6_only = false;
static int output_rows = 20;
static int sort_by = ALL;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "tcptop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize the top active TCP sessions - like top, but for TCP\n"
"\n"
"USAGE: tcptop [-h] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    tcptop            # TCP top, refresh every 1s\n"
"    tcptop -p 1216    # only trace PID 1216\n"
"    tcptop -c path    # only trace the given cgroup path\n"
"    tcptop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{ "ipv4", '4', NULL, 0, "trace IPv4 family only", 0 },
	{ "ipv6", '6', NULL, 0, "trace IPv6 family only", 0 },
	{ "nosummary", 'S', NULL, 0, "Skip system summary line", 0 },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen", 0 },
	{ "sort", 's', "SORT", 0, "Sort columns, default all [all, sent, received]", 0 },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

struct info_t {
	struct ip_key_t key;
	struct traffic_t value;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid, rows;
	static int pos_args;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'c':
		cgroup_path = arg;
		cgroup_filtering = true;
		break;
	case 'C':
		clear_screen = false;
		break;
	case 'S':
		no_summary = true;
		break;
	case '4':
		ipv4_only = true;
		if (ipv6_only) {
			warn("Only one --ipvX option should be used\n");
			argp_usage(state);
		}
		break;
	case '6':
		ipv6_only = true;
		if (ipv4_only) {
			warn("Only one --ipvX option should be used\n");
			argp_usage(state);
		}
		break;
	case 's':
		if (!strcmp(arg, "all")) {
			sort_by = ALL;
		} else if (!strcmp(arg, "sent")) {
			sort_by = SENT;
		} else if (!strcmp(arg, "received")) {
			sort_by = RECEIVED;
		} else {
			warn("invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		errno = 0;
		rows = strtol(arg, NULL, 10);
		if (errno || rows <= 0) {
			warn("invalid rows: %s\n", arg);
			argp_usage(state);
		}
		output_rows = rows;
		if (output_rows > OUTPUT_ROWS_LIMIT)
			output_rows = OUTPUT_ROWS_LIMIT;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0) {
				warn("invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			count = strtol(arg, NULL, 10);
			if (errno || count <= 0) {
				warn("invalid count\n");
				argp_usage(state);
			}
		} else {
			warn("unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int sort_column(const void *obj1, const void *obj2)
{
	struct info_t *i1 = (struct info_t *)obj1;
	struct info_t *i2 = (struct info_t *)obj2;

	if (i1->key.family != i2->key.family)
		/*
		 * i1 - i2 because we want to sort by increasing order (first AF_INET then
		 * AF_INET6).
		 */
		return i1->key.family - i2->key.family;

	if (sort_by == SENT)
		return i2->value.sent - i1->value.sent;
	else if (sort_by == RECEIVED)
		return i2->value.received - i1->value.received;
	else
		return (i2->value.sent + i2->value.received) - (i1->value.sent + i1->value.received);
}

static int print_stat(struct tcptop_bpf *obj)
{
	FILE *f;
	time_t t;
	struct tm *tm;
	char ts[16], buf[256];
	struct ip_key_t key, *prev_key = NULL;
	static struct info_t infos[OUTPUT_ROWS_LIMIT];
	int n, i, err = 0;
	int fd = bpf_map__fd(obj->maps.ip_map);
	int rows = 0;
	bool ipv6_header_printed = false;
	int pid_max_fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	int pid_maxlen = read(pid_max_fd, buf, sizeof buf) - 1;

	if (pid_maxlen < 6)
		pid_maxlen = 6;
	close(pid_max_fd);

	if (!no_summary) {
		f = fopen("/proc/loadavg", "r");
		if (f) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			memset(buf, 0, sizeof(buf));
			n = fread(buf, 1, sizeof(buf), f);
			if (n)
				printf("%8s loadavg: %s\n", ts, buf);
			fclose(f);
		}
	}

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &infos[rows].key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_lookup_elem(fd, &infos[rows].key, &infos[rows].value);
		if (err) {
			warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &infos[rows].key;
		rows++;
	}

	printf("%-*s %-12s %-21s %-21s %6s %6s\n",
				 pid_maxlen, "PID", "COMM", "LADDR", "RADDR",
				 "RX_KB", "TX_KB");

	qsort(infos, rows, sizeof(struct info_t), sort_column);
	rows = rows < output_rows ? rows : output_rows;
	for (i = 0; i < rows; i++) {
		/* Default width to fit IPv4 plus port. */
		int column_width = 21;
		struct ip_key_t *key = &infos[i].key;
		struct traffic_t *value = &infos[i].value;

		if (key->family == AF_INET6) {
			/* Width to fit IPv6 plus port. */
			column_width = 51;
			if (!ipv6_header_printed) {
				printf("\n%-*s %-12s %-51s %-51s %6s %6s\n",
							pid_maxlen, "PID", "COMM", "LADDR6",
							"RADDR6", "RX_KB", "TX_KB");
				ipv6_header_printed = true;
			}
		}

		char saddr[INET6_ADDRSTRLEN];
		char daddr[INET6_ADDRSTRLEN];

		inet_ntop(key->family, &key->saddr, saddr, INET6_ADDRSTRLEN);
		inet_ntop(key->family, &key->daddr, daddr, INET6_ADDRSTRLEN);

		/*
		 * A port is stored in u16, so highest value is 65535, which is 5
		 * characters long.
		 * We need one character more for ':'.
		 */
		size_t size = INET6_ADDRSTRLEN + PORT_LENGTH + 1;

		char saddr_port[size];
		char daddr_port[size];

		snprintf(saddr_port, size, "%s:%d", saddr, key->lport);
		snprintf(daddr_port, size, "%s:%d", daddr, key->dport);

		printf("%-*d %-12.12s %-*s %-*s %6ld %6ld\n",
					 pid_maxlen, key->pid, key->name,
					 column_width, saddr_port,
					 column_width, daddr_port,
					 value->received / 1024, value->sent / 1024);
	}

	printf("\n");

	prev_key = NULL;
	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_delete_elem(fd, &key);
		if (err) {
			warn("bpf_map_delete_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}

	return err;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct tcptop_bpf *obj;
	int family;
	int cgfd = -1;
	int zero = 0;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	family = -1;
	if (ipv4_only)
		family = AF_INET;
	if (ipv6_only)
		family = AF_INET6;

	obj = tcptop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	struct filter_cfg_t filter_cfg = {
		.filter_cg = cgroup_filtering,
		.target_pid = target_pid,
		.target_family = family,
	};

	err = tcptop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	int filter_cfg_fd = bpf_map__fd(obj->maps.filter_cfg_map);
	if (bpf_map_update_elem(filter_cfg_fd, &zero, &filter_cfg, BPF_ANY)) {
		warn("Failed to update filter config map\n");
		goto cleanup;
	}

	if (cgroup_filtering) {
		int cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);

		cgfd = open(cgroup_path, O_RDONLY);
		if (cgfd < 0) {
			warn("Failed opening Cgroup path: %s\n", cgroup_path);
			goto cleanup;
		}

		warn("bpf_map__fd: %d\n", cg_map_fd);

		if (bpf_map_update_elem(cg_map_fd, &zero, &cgfd, BPF_ANY)) {
			warn("Failed adding target cgroup to map\n");
			goto cleanup;
		}
	}

	err = tcptop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (1) {
		sleep(interval);

		if (clear_screen) {
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_stat(obj);
		if (err)
			goto cleanup;

		count--;
		if (exiting || !count)
			goto cleanup;
	}

cleanup:
	if (cgroup_filtering && cgfd != -1)
		close(cgfd);
	tcptop_bpf__destroy(obj);

	return err != 0;
}
