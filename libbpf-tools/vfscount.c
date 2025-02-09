// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Tiago Ilieve
//
// Based on vfscount(8) from BCC by Brendan Gregg.
// 15-Apr-2024   Tiago Ilieve   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "string_helpers.h"
#include "trace_helpers.h"
#include "vfscount.h"
#include "vfscount.skel.h"

static volatile sig_atomic_t exiting = 0;

struct env {
	bool verbose;
	int time;
} env = {
	.time = 99999999,
};

struct row {
	__u64 addr;
	__u64 count;
	const char *func;
};

const char *argp_program_version = "vfscount 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Count VFS calls (\"vfs_*\").\n"
"\n"
"USAGE: vfscount [TIME] [--help]\n"
"\n"
"EXAMPLES:\n"
"    vfscount           # count vfs_* syscalls indefinitely\n"
"    vfscount 5         # count for 5 seconds\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		if (pos_args == 0) {
			errno = 0;
			env.time = strtol(arg, NULL, 10);
			if (errno || env.time == 0) {
				fprintf(stderr, "invalid time\n");
				argp_usage(state);
			}
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
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

int cmp_row(const void *a, const void *b)
{
	struct row *row_a = (struct row *) a;
	struct row *row_b = (struct row *) b;
	return row_a->count - row_b->count;
}

void print_summary(struct ksyms *ksyms, int fd, int max_rows)
{
	struct key_t lookup_key = {}, next_key;
	const struct ksym *ksym;
	struct row *rows;
	__u64 val;
	int total;
	int err;
	int i;

	rows = (struct row *) malloc(max_rows * sizeof(struct row));
	if (rows == NULL) {
		fprintf(stderr, "malloc failed\n");
		return;
	}

	i = 0;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &val);
		if (err) {
			fprintf(stderr, "bpf_map_lookup_elem failed: %s\n", strerror(errno));
			goto err_out;
		}

		ksym = ksyms__map_addr(ksyms, next_key.ip);

		rows[i].addr = next_key.ip;
		rows[i].count = val;
		rows[i].func = ksym->name;

		lookup_key = next_key;
		i++;
	}
	total = i;

	qsort(rows, total, sizeof(struct row), cmp_row);

	printf("\n%-16s %-26s %8s\n",  "ADDR", "FUNC", "COUNT");
	for (int i = 0; i < total; i++) {
		printf("%-16llx %-26s %8llu\n",  rows[i].addr, rows[i].func, rows[i].count);
	}

err_out:
	free(rows);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct string_array *funcs = NULL;
	struct bpf_link **links = NULL;
	struct vfscount_bpf *obj;
	struct ksyms *ksyms;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = vfscount_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open and load BPF object\n");
		return 1;
	}

	ksyms = ksyms__load();
	if (ksyms == NULL) {
		fprintf(stderr, "failed to load ksyms\n");
		goto cleanup;
	}

	funcs = ksyms__get_symbols_re(ksyms, "^vfs_.*");
	if (funcs == NULL) {
		fprintf(stderr, "failed to filter ksyms by regex\n");
		goto cleanup;
	}

	links = (struct bpf_link **) malloc(funcs->size * sizeof(struct bpf_link *));
	if (links == NULL) {
		fprintf(stderr, "malloc failed\n");
		goto cleanup;
	}

	for (int i = 0; i < funcs->size; i++) {
		if (!kprobe_exists(funcs->data[i])) {
			links[i] = NULL;
			continue;
		}
		links[i] = bpf_program__attach_kprobe(obj->progs.dummy_kprobe, false, funcs->data[i]);
		if (!links[i]) {
			fprintf(stderr, "failed to attach BPF object for: %s\n", funcs->data[i]);
		}
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* print header */
	printf("Tracing... Ctrl-C to end.\n");

	while (!exiting) {
		sleep(env.time);
		break;
	}

	print_summary(ksyms, bpf_map__fd(obj->maps.counts), funcs->size);

cleanup:
	if (links != NULL) {
		for (int i = 0; i < funcs->size; i++)
			bpf_link__destroy(links[i]);
		free(links);
	}
	string_array__free(funcs);
	ksyms__free(ksyms);
	vfscount_bpf__destroy(obj);

	return err != 0;
}
