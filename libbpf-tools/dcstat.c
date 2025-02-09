// SPDX-License-Identifier: GPL-2.0
// Copyright 2024 Sony Group Corporation
//
// Based on dcstat(8) from BCC by Brendan Gregg

#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf.h>
#include "dcstat.h"
#include "dcstat.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

const char *argp_program_version = "dcstat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char argp_program_doc[] =
	"\ndcstat: Count various disk cache statistics\n"
	"\n"
	"EXAMPLES:\n"
	"    dcstat      # interval one second\n"
	"    dcstat 5 3  # interval five seconds, three output lines\n";
static char args_doc[] = "[interval [count]]";

static const struct argp_option opts[] =
{
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static struct env
{
	bool verbose;
	int count;
	int interval;
} env = {
	.interval = 1,
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long interval;
	long count;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
		case 0:
			errno = 0;
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0 || interval > INT_MAX) {
				fprintf(stderr, "invalid interval: %s\n", arg);
				argp_usage(state);
			}
			env.interval = interval;
			break;
		case 1:
			errno = 0;
			count = strtol(arg, NULL, 10);
			if (errno || count < 0 || count > INT_MAX) {
				fprintf(stderr, "invalid count: %s\n", arg);
				argp_usage(state);
			}
			env.count = count;
			break;
		default:
			argp_usage(state);
			break;
		}
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

static const char *strftime_now(char *s, size_t max, const char *format)
{
	struct tm *tm;
	time_t t;

	t = time(NULL);
	tm = localtime(&t);
	if (tm == NULL) {
		fprintf(stderr, "localtime: %s\n", strerror(errno));
		return "<failed>";
	}

	if (strftime(s, max, format, tm) == 0) {
		fprintf(stderr, "strftime error\n");
		return "<failed>";
	}

	return s;
}

static const char *stat_types_names[] =
{
	[S_REFS] = "REFS",
	[S_SLOW] = "SLOW",
	[S_MISS] = "MISS",
};

void print_header(void)
{
	int i;

	printf("%-8s  ", "TIME");
	for (i = 0; i < S_MAXSTAT; i++) {
		printf("%8s/s", stat_types_names[i]);
	}
	printf("  %-8s\n", "HITS");
}

static void print_and_reset_stats(__u64 stats[S_MAXSTAT])
{
	char s[16];
	__u64 val, ref, miss, hit;
	double pct = 0;
	int i;

	printf("%-8s: ", strftime_now(s, sizeof(s), "%H:%M:%S"));
	for (i = 0; i < S_MAXSTAT; i++) {
		val = __atomic_exchange_n(&stats[i], 0, __ATOMIC_RELAXED);
		if (i == 0)
			ref = val;
		if (i == 2)
			miss = val;
		printf(" %8llu", val / env.interval);
	}
	hit = ref - miss;
	pct = 100.0 * hit / ref;
	printf(" %8.2f\n", pct);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
		.args_doc = args_doc,
	};
	struct dcstat_bpf *skel;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return 1;
	}

	skel = dcstat_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skelect\n");
		return 1;
	}

	err = dcstat_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skelect: %d\n", err);
		goto cleanup;
	}

	if (!skel->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux "
			"5.7, please upgrade.\n");
		goto cleanup;
	}

	err = dcstat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %s\n",
		strerror(-err));
		goto cleanup;
	}

	print_header();
	do {
		sleep(env.interval);
		print_and_reset_stats(skel->bss->stats);
	} while (!env.count || --env.count);

cleanup:
	dcstat_bpf__destroy(skel);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
