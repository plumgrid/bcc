#!/usr/bin/env python
#
# kvmexit.py
#
# Display the exit_reason and its statistics of each vm exit
# for all vcpus of all virtual machines. For example:
# $./kvmexit.py
# PID      TID      KVM_EXIT_REASON                     COUNT EXIT_TIME_AVG
# 9352     9385     EXTERNAL_INTERRUPT                  4        6600
# 9352     9385     HLT                                 697      67104726
# 9352     9385     MSR_READ                            47       1519
# 9352     9385     MSR_WRITE                           2295     1616
#  ...
#
# Besides, we also allow users to specify one pid, tid(s), or one
# pid and its vcpu. See kvmexit_example.txt for more examples.
#
# @PID: each vitual machine's pid in the user space.
# @TID: the user space's thread of each vcpu of that virtual machine.
# @KVM_EXIT_REASON: the reason why the vm exits.
# @COUNT: the counts of the @KVM_EXIT_REASONS.
# @EXIT_TIME_AVG: the average of all interval from kvm_exit to the next kvm_entry. unit:ns
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support)
#
# Copyright (c) 2021 ByteDance Inc. All rights reserved.
#
# Author(s):
#   Fei Li <lifei.shirley@bytedance.com>


from __future__ import print_function
from time import sleep
from bcc import BPF
import argparse
import multiprocessing
import os
import subprocess

#
# Process Arguments
#
def valid_args_list(args):
    args_list = args.split(",")
    for arg in args_list:
        try:
            int(arg)
        except:
            raise argparse.ArgumentTypeError("must be valid integer")
    return args_list

# arguments
examples = """examples:
    ./kvmexit                              # Display kvm_exit_reason and its statistics in real-time until Ctrl-C
    ./kvmexit 5                            # Display in real-time after sleeping 5s
    ./kvmexit -p 3195281                   # Collpase all tids for pid 3195281 with exit reasons sorted in descending order
    ./kvmexit -p 3195281 20                # Collpase all tids for pid 3195281 with exit reasons sorted in descending order, and display after sleeping 20s
    ./kvmexit -p 3195281 -v 0              # Display only vcpu0 for pid 3195281, descending sort by default
    ./kvmexit -p 3195281 -a                # Display all tids for pid 3195281
    ./kvmexit -t 395490                    # Display only for tid 395490 with exit reasons sorted in descending order
    ./kvmexit -t 395490 20                 # Display only for tid 395490 with exit reasons sorted in descending order after sleeping 20s
    ./kvmexit -T '395490,395491'           # Display for a union like {395490, 395491}
"""
parser = argparse.ArgumentParser(
    description="Display kvm_exit_reason and its statistics at a timed interval",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("duration", nargs="?", default=99999999, type=int, help="show delta for next several seconds")
parser.add_argument("-p", "--pid", type=int, help="trace this PID only")
exgroup = parser.add_mutually_exclusive_group()
exgroup.add_argument("-t", "--tid", type=int, help="trace this TID only")
exgroup.add_argument("-T", "--tids", type=valid_args_list, help="trace a comma separated series of tids with no space in between")
exgroup.add_argument("-v", "--vcpu", type=int, help="trace this vcpu only")
exgroup.add_argument("-a", "--alltids", action="store_true", help="trace all tids for this pid")
args = parser.parse_args()
duration = int(args.duration)

#
# Setup BPF
#

# load BPF program
bpf_text = """
#include <linux/delay.h>

#define REASON_NUM 76
#define TGID_NUM 1024


typedef struct kvm_exit {
    u64 count;
    u64 exit_ts;    //timestamp of kvm_exit
    u64 entry_ts;   //timestamp of kvm_entry after kvm_exit for the same vcpu thread.
    u64 sum_hd;     //the sum of the duration of all exiting status
}kvm_exit_t;

struct exit_count {
    u32 reason;
    kvm_exit_t kvm_exit[REASON_NUM];
};
BPF_PERCPU_ARRAY(init_value, struct exit_count, 1);
BPF_TABLE("percpu_hash", u64, struct exit_count, pcpu_kvm_stat, TGID_NUM);

struct cache_info {
    u64 cache_pid_tgid;
    struct exit_count cache_kvm_exit;
};
BPF_PERCPU_ARRAY(pcpu_cache, struct cache_info, 1);

TRACEPOINT_PROBE(kvm, kvm_entry) {
    struct exit_count *tmp_exit_count = NULL;
    kvm_exit_t *tmp_kvm_exit = NULL;
    u64 time_hd = 0;
    u64 cur_tgid_pid = bpf_get_current_pid_tgid();
    struct exit_count *tmp_pcpu_kvm_stat = NULL;
    struct cache_info *tmp_pcpu_cache = NULL;
    int zero = 0;

    tmp_pcpu_cache = pcpu_cache.lookup(&zero);
    if (tmp_pcpu_cache == NULL) {
        return 0;
    }
    if (tmp_pcpu_cache->cache_pid_tgid == cur_tgid_pid) {
        tmp_exit_count = &tmp_pcpu_cache->cache_kvm_exit;
    } else {
        tmp_pcpu_kvm_stat = pcpu_kvm_stat.lookup(&cur_tgid_pid);
        if(tmp_pcpu_kvm_stat == NULL) {
            return 0;
        }
        tmp_exit_count = tmp_pcpu_kvm_stat;
    }

    if (tmp_exit_count->reason >= REASON_NUM) {
        return 0;
    }
    tmp_kvm_exit = &tmp_exit_count->kvm_exit[tmp_exit_count->reason];

    tmp_kvm_exit->entry_ts = bpf_ktime_get_ns();

    // time_hd is time interval from kvm_exit to next kvm_entry
    time_hd = tmp_kvm_exit->entry_ts - tmp_kvm_exit->exit_ts;
    tmp_kvm_exit->sum_hd += time_hd;

    return 0;
}

TRACEPOINT_PROBE(kvm, kvm_exit) {
    int cache_miss = 0;
    int zero = 0;
    u32 er = args->exit_reason;
    if (er >= REASON_NUM) {
        return 0;
    }

    u64 cur_pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = cur_pid_tgid >> 32;
    u32 pid = cur_pid_tgid;

    if (THREAD_FILTER)
        return 0;

    struct exit_count *tmp_info = NULL, *initial = NULL;
    struct cache_info *cache_p;
    cache_p = pcpu_cache.lookup(&zero);
    if (cache_p == NULL) {
        return 0;
    }

    if (cache_p->cache_pid_tgid == cur_pid_tgid) {
        //a. If the cur_pid_tgid hit this physical cpu consecutively, save it to pcpu_cache
        tmp_info = &cache_p->cache_kvm_exit;
    } else {
        //b. If another pid_tgid matches this pcpu for the last hit, OR it is the first time to hit this physical cpu.
        cache_miss = 1;

        // b.a Try to load the last cache struct if exists.
        tmp_info = pcpu_kvm_stat.lookup(&cur_pid_tgid);

        // b.b If it is the first time for the cur_pid_tgid to hit this pcpu, employ a
        // per_cpu array to initialize pcpu_kvm_stat's exit_count with each exit reason's count is zero
        if (tmp_info == NULL) {
            initial = init_value.lookup(&zero);
            if (initial == NULL) {
                return 0;
            }

            pcpu_kvm_stat.update(&cur_pid_tgid, initial);
            tmp_info = pcpu_kvm_stat.lookup(&cur_pid_tgid);
            // To pass the verifier
            if (tmp_info == NULL) {
                return 0;
            }
        }
    }

    if (er < REASON_NUM) {
        tmp_info->reason = er;
        tmp_info->kvm_exit[er].count++;
        tmp_info->kvm_exit[er].exit_ts = bpf_ktime_get_ns();
        if (cache_miss == 1) {
            if (cache_p->cache_pid_tgid != 0) {
                // b.*.a Let's save the last hit cache_info into kvm_stat.
                pcpu_kvm_stat.update(&cache_p->cache_pid_tgid, &cache_p->cache_kvm_exit);
            }
            // b.* As the cur_pid_tgid meets current pcpu_cache_array for the first time, save it.
            cache_p->cache_pid_tgid = cur_pid_tgid;
            bpf_probe_read(&cache_p->cache_kvm_exit, sizeof(*tmp_info), tmp_info);
        }
        return 0;
    }

    return 0;
}
"""

# format output
exit_reasons = (
    "EXCEPTION_NMI",
    "EXTERNAL_INTERRUPT",
    "TRIPLE_FAULT",
    "INIT_SIGNAL",
    "N/A",
    "N/A",
    "N/A",
    "INTERRUPT_WINDOW",
    "NMI_WINDOW",
    "TASK_SWITCH",
    "CPUID",
    "N/A",
    "HLT",
    "INVD",
    "INVLPG",
    "RDPMC",
    "RDTSC",
    "N/A",
    "VMCALL",
    "VMCLEAR",
    "VMLAUNCH",
    "VMPTRLD",
    "VMPTRST",
    "VMREAD",
    "VMRESUME",
    "VMWRITE",
    "VMOFF",
    "VMON",
    "CR_ACCESS",
    "DR_ACCESS",
    "IO_INSTRUCTION",
    "MSR_READ",
    "MSR_WRITE",
    "INVALID_STATE",
    "MSR_LOAD_FAIL",
    "N/A",
    "MWAIT_INSTRUCTION",
    "MONITOR_TRAP_FLAG",
    "N/A",
    "MONITOR_INSTRUCTION",
    "PAUSE_INSTRUCTION",
    "MCE_DURING_VMENTRY",
    "N/A",
    "TPR_BELOW_THRESHOLD",
    "APIC_ACCESS",
    "EOI_INDUCED",
    "GDTR_IDTR",
    "LDTR_TR",
    "EPT_VIOLATION",
    "EPT_MISCONFIG",
    "INVEPT",
    "RDTSCP",
    "PREEMPTION_TIMER",
    "INVVPID",
    "WBINVD",
    "XSETBV",
    "APIC_WRITE",
    "RDRAND",
    "INVPCID",
    "VMFUNC",
    "ENCLS",
    "RDSEED",
    "PML_FULL",
    "XSAVES",
    "XRSTORS",
    "N/A",
    "N/A",
    "UMWAIT",
    "TPAUSE"
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "BUS_LOCK",
    "NOTIFY",
)

#
# Do some checks
#
try:
    # Currently, only adapte on intel architecture
    cmd = "cat /proc/cpuinfo | grep vendor_id | head -n 1"
    arch_info = subprocess.check_output(cmd, shell=True).strip()
    if b"Intel" in arch_info:
        pass
    else:
        raise Exception("Currently we only support Intel architecture, please do expansion if needs more.")

    # Check if kvm module is loaded
    if os.access("/dev/kvm", os.R_OK | os.W_OK):
        pass
    else:
        raise Exception("Please insmod kvm module to use kvmexit tool.")
except Exception as e:
    raise Exception("Failed to do precondition check, due to: %s." % e)


def find_tid(tgt_dir, tgt_vcpu):
    for tid in os.listdir(tgt_dir):
        path = tgt_dir + "/" + tid + "/comm"
        fp = open(path, "r")
        comm = fp.read()
        if (comm.find(tgt_vcpu) != -1):
            return tid
    return -1

# set process/thread filter
thread_context = ""
header_format = ""
need_collapse = not args.alltids
if args.tid is not None:
    thread_context = "TID %s" % args.tid
    thread_filter = 'pid != %s' % args.tid
elif args.tids is not None:
    thread_context = "TIDS %s" % args.tids
    thread_filter = "pid != " + " && pid != ".join(args.tids)
    header_format = "TIDS     "
elif args.pid is not None:
    thread_context = "PID %s" % args.pid
    thread_filter = 'tgid != %s' % args.pid
    if args.vcpu is not None:
        thread_context = "PID %s VCPU %s" % (args.pid, args.vcpu)
        # transfer vcpu to tid
        tgt_dir = '/proc/' + str(args.pid) + '/task'
        tgt_vcpu = "CPU " + str(args.vcpu)
        args.tid = find_tid(tgt_dir, tgt_vcpu)
        if args.tid == -1:
            raise Exception("There's no v%s for PID %d." % (tgt_vcpu, args.pid))
        thread_filter = 'pid != %s' % args.tid
    elif args.alltids:
        thread_context = "PID %s and its all threads" % args.pid
        header_format = "TID      "
else:
    thread_context = "all threads"
    thread_filter = '0'
    header_format = "PID      TID      "
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)

b = BPF(text=bpf_text)


# header
print("Display kvm exit reasons and statistics for %s" % thread_context, end="")
if duration < 99999999:
    print(" after sleeping %d secs." % duration)
else:
    print("... Hit Ctrl-C to end.")

try:
    sleep(duration)
except KeyboardInterrupt:
    print()


# Currently, sort multiple tids in descending order is not supported.
if (args.pid or args.tid):
    ct_reason = []
    if args.pid:
        tgid_exit = [0 for i in range(len(exit_reasons))]

# output
print("%s%-35s %s %s" % (header_format, "KVM_EXIT_REASON", "COUNT", "EXIT_TIME_AVG"))

pcpu_kvm_stat = b["pcpu_kvm_stat"]
pcpu_cache = b["pcpu_cache"]
for k, v in pcpu_kvm_stat.items():
    tgid = k.value >> 32
    pid = k.value & 0xffffffff
    for i in range(0, len(exit_reasons)):
        count_sum = 0
        time_sum = 0
        for inner_cpu in range(0, multiprocessing.cpu_count()):
            cachePIDTGID = pcpu_cache[0][inner_cpu].cache_pid_tgid
            # Take priority to check if it is in cache
            if cachePIDTGID == k.value:
                count_sum += pcpu_cache[0][inner_cpu].cache_kvm_exit.kvm_exit[i].count
                time_sum += pcpu_cache[0][inner_cpu].cache_kvm_exit.kvm_exit[i].sum_hd
            # If not in cache, find from kvm_stat
            else:
                count_sum += v[inner_cpu].kvm_exit[i].count
                time_sum += v[inner_cpu].kvm_exit[i].sum_hd
        if count_sum == 0:
            continue
        avg_time = int(time_sum / count_sum)

        if (args.pid and args.pid == tgid and need_collapse):
            tgid_exit[i] += count_sum
        elif (args.tid and args.tid == pid):
            ct_reason.append((count_sum, i, avg_time))
        elif not need_collapse or args.tids:
            print("%-8u %-35s %-8u %-12u" % (pid, exit_reasons[i], count_sum, avg_time))
        else:
            print("%-8u %-8u %-35s %-8u %-12u" % (tgid, pid, exit_reasons[i], count_sum, avg_time))

    # Display only for the target tid in descending sort
    if (args.tid and args.tid == pid):
        ct_reason.sort(reverse=True)
        for i in range(0, len(ct_reason)):
            if ct_reason[i][0] == 0:
                continue
            print("%-35s %-8u %-12u" % (exit_reasons[ct_reason[i][1]], ct_reason[i][0], ct_reason[i][2]))
        break


# Aggregate all tids' counts for this args.pid in descending sort
if args.pid and need_collapse:
    for i in range(0, len(exit_reasons)):
        ct_reason.append((tgid_exit[i], i))
    ct_reason.sort(reverse=True)
    for i in range(0, len(ct_reason)):
        if ct_reason[i][0] == 0:
            continue
        print("%-35s %-8u" % (exit_reasons[ct_reason[i][1]], ct_reason[i][0]))
