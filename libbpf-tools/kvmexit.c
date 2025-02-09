/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * kvmexit  Trace kvm exit and show exit reason stat.
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on kvmexit(8) from BCC by Fei Li.
 * 21-Sep-2021  Hengqi Chen   Created this.
 */
#define _GNU_SOURCE
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "kvmexit.h"
#include "kvmexit.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT	1024
#define MAX_EXIT_REASON		127

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static pid_t target_tid = 0;
static char *target_tids = NULL;
static int target_vcpu = -1;
static bool trace_by_process = true;
static int duration = 0;

static const char *exit_reason[] = {
	[0] = "EXCEPTION_NMI",
	[1] = "EXTERNAL_INTERRUPT",
	[2] = "TRIPLE_FAULT",
	[3] = "INIT_SIGNAL",
	[4] = "SIPI_SIGNAL",
	[7] = "INTERRUPT_WINDOW",
	[8] = "NMI_WINDOW",
	[9] = "TASK_SWITCH",
	[10] = "CPUID",
	[12] = "HLT",
	[13] = "INVD",
	[14] = "INVLPG",
	[15] = "RDPMC",
	[16] = "RDTSC",
	[18] = "VMCALL",
	[19] = "VMCLEAR",
	[20] = "VMLAUNCH",
	[21] = "VMPTRLD",
	[22] = "VMPTRST",
	[23] = "VMREAD",
	[24] = "VMRESUME",
	[25] = "VMWRITE",
	[26] = "VMOFF",
	[27] = "VMON",
	[28] = "CR_ACCESS",
	[29] = "DR_ACCESS",
	[30] = "IO_INSTRUCTION",
	[31] = "MSR_READ",
	[32] = "MSR_WRITE",
	[33] = "INVALID_STATE",
	[34] = "MSR_LOAD_FAIL",
	[36] = "MWAIT_INSTRUCTION",
	[37] = "MONITOR_TRAP_FLAG",
	[39] = "MONITOR_INSTRUCTION",
	[40] = "PAUSE_INSTRUCTION",
	[41] = "MCE_DURING_VMENTRY",
	[43] = "TPR_BELOW_THRESHOLD",
	[44] = "APIC_ACCESS",
	[45] = "EOI_INDUCED",
	[46] = "GDTR_IDTR",
	[47] = "LDTR_TR",
	[48] = "EPT_VIOLATION",
	[49] = "EPT_MISCONFIG",
	[50] = "INVEPT",
	[51] = "RDTSCP",
	[52] = "PREEMPTION_TIMER",
	[53] = "INVVPID",
	[54] = "WBINVD",
	[55] = "XSETBV",
	[56] = "APIC_WRITE",
	[57] = "RDRAND",
	[58] = "INVPCID",
	[59] = "VMFUNC",
	[60] = "ENCLS",
	[61] = "RDSEED",
	[62] = "PML_FULL",
	[63] = "XSAVES",
	[64] = "XRSTORS",
	[67] = "UMWAIT",
	[68] = "TPAUSE",
	[MAX_EXIT_REASON] = "N/A",
};

const char *argp_program_version = "kvmexit 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace kvm exit and show exit reason stat.\n"
"\n"
"USAGE: kvmexit [-h] [-p PID] [-t TID] [-a] [DURATION]\n"
"\n"
"EXAMPLES:\n"
"    kvmexit                # Trace kvm exit reason\n"
"    kvmexit 5              # Trace for 5s\n"
"    kvmexit -p 1216        # Only trace pid 1216\n"
"    kvmexit -p 1216 -a     # Only trace pid 1216, display by thread\n"
"    kvmexit -p 1216 -c 0   # Only trace vCPU 0 of pid 1216\n"
"    kvmexit -T 1216,1217   # Trace pid 1216 and 1217\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "tid", 't', "TID", 0, "Thread ID to trace" },
	{ "tids", 'T', "TIDs", 0, "Comma-separated list of thread id to trace" },
	{ "vcpu", 'c', "vCPU", 0, "Trace this vCPU only" },
	{ "alltids", 'a', NULL, 0, "Display by thread id" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args = 0;
	char *tid;
	long num;

	switch (key) {
	case 'a':
		trace_by_process = false;
		break;
	case 'p':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num <= 0) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = num;
		break;
	case 't':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num <= 0) {
			warn("invalid TID: %s\n", arg);
			argp_usage(state);
		}
		target_tid = num;
		trace_by_process = false;
		break;
	case 'T':
		if (!arg) {
			warn("No thread ids specified\n");
			argp_usage(state);
		}
		tid = strtok(arg, ",");
		while (tid) {
			num = strtol(tid, NULL, 10);
			if (errno || num <= 0) {
				warn("Invalid tids: %s\n", arg);
				argp_usage(state);
			}
			tid = strtok(NULL, ",");
		}
		target_tids = strdup(arg);
		trace_by_process = false;
		break;
	case 'c':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num < 0) {
			warn("invalid vCPU: %s\n", arg);
			argp_usage(state);
		}
		target_vcpu = num;
		trace_by_process = false;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			duration = strtol(arg, NULL, 10);
			if (errno || duration <= 0) {
				warn("invalid duration: %s\n", arg);
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

static int vcpu_to_tid()
{
	char comm_path[PATH_MAX * 2], path[PATH_MAX], comm[80], cpu[80];
	struct dirent *entry;
	DIR *dir;
	FILE *f;
	int err = -1;

	if (target_vcpu == -1)
		return 0;
	snprintf(cpu, sizeof(cpu), "cpu %d\n", target_vcpu);

	if (!target_pid) {
		warn("No pid specified for vCPU %d\n", target_vcpu);
		return -1;
	}

	snprintf(path, sizeof(path), "/proc/%d/task", target_pid);
	dir = opendir(path);
	if (!dir) {
		warn("Failed to open dir %s\n", path);
		return -1;
	}

	while ((entry = readdir(dir))) {
		if (entry->d_type != DT_DIR ||
		   !strcmp(entry->d_name, "..") ||
		   !strcmp(entry->d_name, "."))
			continue;

		snprintf(comm_path, sizeof(comm_path), "%s/%s/comm", path, entry->d_name);
		f = fopen(comm_path, "r");
		if (!f) {
			warn("Failed to open file %s\n", comm_path);
			break;
		}

		if (fgets(comm, sizeof(comm), f) && strcasestr(comm, cpu) != NULL) {
			target_tid = strtol(entry->d_name, NULL, 10);
			err = 0;
			fclose(f);
			break;
		}
		fclose(f);
	}
	closedir(dir);
	return err;
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int sort_by_count(const void *obj1, const void *obj2)
{
	struct exit_stat *v1 = (struct exit_stat *)obj1;
	struct exit_stat *v2 = (struct exit_stat *)obj2;

	return v2->count - v1->count;
}

static void print_stat(struct kvmexit_bpf *obj)
{
	static struct exit_stat values[OUTPUT_ROWS_LIMIT];
	struct exit_key key, *prev_key = NULL;
	int fd = bpf_map__fd(obj->maps.entries);
	int i, err, rows = 0;

	if (trace_by_process)
		printf("%-7s %-20s %-5s\n", "PID", "EXIT_REASON", "COUNT");
	else
		printf("%-7s %-7s %-20s %-5s\n", "PID", "TID", "EXIT_REASON", "COUNT");

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return;
		}
		err = bpf_map_lookup_elem(fd, &key, &values[rows++]);
		if (err) {
			warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return;
		}
		prev_key = &key;
	}

	qsort(values, rows, sizeof(struct exit_stat), sort_by_count);
	for (i = 0; i < rows; i++) {
		struct exit_stat *v = &values[i];
		if (trace_by_process)
			printf("%-7d %-20s %-5d\n",
			       v->pid, exit_reason[v->exit_reason], v->count);
		else
			printf("%-7d %-7d %-20s %-5d\n",
			       v->pid, v->tid, exit_reason[v->exit_reason], v->count);
	}
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct kvmexit_bpf *obj;
	int err, map_fd;
	pid_t tid;
	char *p;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	err = vcpu_to_tid();
	if (err)
		return err;

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = kvmexit_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->target_tid = target_tid;
	obj->rodata->trace_by_process = trace_by_process;
	obj->rodata->filter_by_tid = target_tids != NULL;

	err = kvmexit_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (target_tids) {
		map_fd = bpf_map__fd(obj->maps.tids);
		p = strtok(target_tids, ",");
		while (p) {
			tid = strtol(p, NULL, 10);
			bpf_map_update_elem(map_fd, &tid, &tid, BPF_ANY);
			p = strtok(NULL, ",");
		}
	}

	err = kvmexit_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Tracing kvm exit reason");
	if (duration)
		printf(" for %d secs.\n", duration);
	else
		printf("... Hit Ctrl-C to end.\n");

	if (duration) {
		sleep(duration);
	} else {
		pause();
		printf("\n");
	}
	print_stat(obj);

cleanup:
	kvmexit_bpf__destroy(obj);

	return err != 0;
}
