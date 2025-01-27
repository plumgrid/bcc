// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
// filegone Trace why a file has vanished (either deleted or renamed).
// Copyright 2024 Sony Group Corporation
//
// Based on filegone from BCC by Curu.
//

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "filegone.h"
#include "filegone.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100

static volatile sig_atomic_t exiting = 0;

static struct env {
	pid_t pid;
	bool verbose;
} env = {};

const char *argp_program_version = "filegone 0.1";
const char *argp_program_bug_address =
"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace why a file has vanished (either deleted or renamed).\n"
"\n"
"USAGE: filegone  [--help] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    filegone         # trace all events\n"
"    filegone -p 123  # trace pid 123\n";

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Process PID to trace"},
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int pid;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

const char *action2str(char action)
{
	return (action == 'D') ? "DELETE" : "RENAME";
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const char *action_str;
	char file_str[96];
	struct event e;
	struct tm *tm;
	char ts[32];
	time_t t;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));
	action_str = action2str(e.action);

	if (strcmp(action_str, "RENAME") == 0) {
		strncpy(file_str, e.fname, sizeof(file_str) - 1);
		strncat(file_str, " > ", sizeof(file_str) - strlen(file_str) - 1);
		strncat(file_str, e.fname2, sizeof(file_str) - strlen(file_str) - 1);
	} else {
		strncpy(file_str, e.fname, sizeof(file_str) - 1);
	}

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-6d %-16s %-6s %s\n",
	       ts, e.tgid, e.task, action_str,
	       file_str);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct filegone_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = filegone_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_tgid = env.pid;

	err = filegone_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = filegone_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing deleted or renamed files ... Hit Ctrl-C to end.\n");
	printf("%-8s %-6s %-16s %-6s %s\n", "TIME", "PID", "COMM", "ACTION", "FILE");

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* Reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	filegone_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
}
