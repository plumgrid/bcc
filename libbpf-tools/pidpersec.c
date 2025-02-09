// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Tiago Ilieve
//
// Based on pidpersec(8) from BCC by Brendan Gregg.
// 12-Apr-2024   Tiago Ilieve   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "pidpersec.h"
#include "pidpersec.skel.h"

static volatile sig_atomic_t exiting = 0;

struct env {
	bool verbose;
} env = {};

const char *argp_program_version = "pidpersec 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Count new processes (via fork).\n"
"\n"
"USAGE: pidpersec [--help]\n"
"\n"
"EXAMPLES:\n"
"    pidpersec  # count new processes\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct pidpersec_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = pidpersec_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open and load BPF object\n");
		return 1;
	}

	err = pidpersec_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF object\n");
		return 1;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* print header */
	printf("Tracing... Ctrl-C to end.\n");

	while (!exiting) {
		struct tm *tm;
		char ts[16];
		__u64 val;
		time_t t;

		sleep(1);

		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		val = __atomic_exchange_n(&obj->bss->stats[S_COUNT], 0, __ATOMIC_RELAXED);
		printf("%s: PIDs/sec: %llu\n", ts, val);
	}

cleanup:
	pidpersec_bpf__destroy(obj);

	return err != 0;
}
