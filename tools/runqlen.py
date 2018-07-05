#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# runqlen    Summarize scheduler run queue length as a histogram.
#            For Linux, uses BCC, eBPF.
#
# This counts the length of the run queue, excluding the currently running
# thread, and shows it as a histogram.
#
# Also answers run queue occupancy.
#
# USAGE: runqlen [-h] [-T] [-Q] [-m] [-D] [interval] [count]
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support). Under tools/old is
# a version of this tool that may work on Linux 4.6 - 4.8.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Dec-2016   Brendan Gregg   Created this.
# 05-Jul-2018   Michael D. Day converted to a class

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from time import sleep, strftime
from tempfile import NamedTemporaryFile
from os import open, close, dup, unlink, O_WRONLY



class renqlen_sensor:

    # define BPF program
    bpf_text = """
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>

    // Declare enough of cfs_rq to find nr_running, since we can't #import the
    // header. This will need maintenance. It is from kernel/sched/sched.h:
    struct cfs_rq_partial {
        struct load_weight load;
        RUNNABLE_WEIGHT_FIELD
        unsigned int nr_running, h_nr_running;
    };

    typedef struct cpu_key {
        int cpu;
        unsigned int slot;
    } cpu_key_t;
    STORAGE

    int do_perf_event()
    {
        unsigned int len = 0;
        pid_t pid = 0;
        struct task_struct *task = NULL;
        struct cfs_rq_partial *my_q = NULL;

        // Fetch the run queue length from task->se.cfs_rq->nr_running. This is an
        // unstable interface and may need maintenance. Perhaps a future version
        // of BPF will support task_rq(p) or something similar as a more reliable
        // interface.
        task = (struct task_struct *)bpf_get_current_task();
        my_q = (struct cfs_rq_partial *)task->se.cfs_rq;
        len = my_q->nr_running;

        // Calculate run queue length by subtracting the currently running task,
        // if present. len 0 == idle, len 1 == one running task.
        if (len > 0)
            len--;

        STORE

        return 0;
    }
    """

  # Define the bpf program for checking purpose
    bpf_check_text = """
    #include <linux/sched.h>
    unsigned long dummy(struct sched_entity *entity)
    {
        return entity->runnable_weight;
    }
    """


    def __init__(self, args, debug = 0, frequency = 99):

        # code substitutions
        if args.cpus:
            self.bpf_text = self.bpf_text.replace('STORAGE',
                'BPF_HISTOGRAM(dist, cpu_key_t);')
            self.bpf_text = self.bpf_text.replace('STORE', 'cpu_key_t key = {.slot = len}; ' +
                                        'key.cpu = bpf_get_smp_processor_id(); ' +
                                        'dist.increment(key);')
        else:
            self.bpf_text = self.bpf_text.replace('STORAGE',
                'BPF_HISTOGRAM(dist, unsigned int);')
            self.bpf_text = self.bpf_text.replace('STORE', 'dist.increment(len);')

        if self.check_runnable_weight_field():
            self.bpf_text = self.bpf_text.replace('RUNNABLE_WEIGHT_FIELD', 'unsigned long runnable_weight;')
        else:
            self.bpf_text = self.bpf_text.replace('RUNNABLE_WEIGHT_FIELD', '')

        if debug or args.ebpf:
            print(self.bpf_text)
            if args.ebpf:
                exit()
        countdown = int(args.count)
        samples = 0
        # initialize BPF & perf_events
        b = BPF(text=self.bpf_text)
        b.attach_perf_event(ev_type=PerfType.SOFTWARE,
            ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
            sample_period=0, sample_freq=frequency)

        if not args.json:
            print("Sampling run queue length... Hit Ctrl-C to end.")

        # output
        exiting = 0 if args.interval else 1
        dist = b.get_table("dist")
        while (1):
            try:
                sleep(int(args.interval))
            except KeyboardInterrupt:
                exiting = 1

            print()
            if args.timestamp:
                if not args.json:
                    print("%-8s\n" % strftime("%H:%M:%S"), end="")

            if args.runqocc:
                if args.cpus:
                    # run queue occupancy, per-CPU summary
                    idle = {}
                    queued = {}
                    cpumax = 0
                    for k, v in dist.items():
                        if k.cpu > cpumax:
                            cpumax = k.cpu
                    for c in range(0, cpumax + 1):
                        idle[c] = 0
                        queued[c] = 0
                    for k, v in dist.items():
                        if k.slot == 0:
                            idle[k.cpu] += v.value
                        else:
                            queued[k.cpu] += v.value
                    for c in range(0, cpumax + 1):
                        samples = idle[c] + queued[c]
                        if samples:
                            runqocc = float(queued[c]) / samples
                        else:
                            runqocc = 0
                        if not args.json:
                            print("runqocc, CPU %-3d %6.2f%%" % (c, 100 * runqocc))
                        else:
                            print('{"tag": runqocc, "timestamp": %-8s, "cpu": %-3d %6.2f%%}' % (strftime("%H:%M:%S"), c, 100 * runqocc))

                else:
                    # run queue occupancy, system-wide summary
                    idle = 0
                    queued = 0
                    for k, v in dist.items():
                        if k.value == 0:
                            idle += v.value
                        else:
                            queued += v.value
                    samples = idle + queued
                    if samples:
                        runqocc = float(queued) / samples
                    else:
                        runqocc = 0
                    if not args.json:
                        print("runqocc: %0.2f%%" % (100 * runqocc))
                    else:
                        print('{"tag": runqocc, "timestamp": %-8s, "val": %0.2f%%}' % (strftime("%H:%M:%S"), 100 * runqocc))

            else:
                # run queue length histograms
                if not args.json:
                    dist.print_linear_hist("runqlen", "cpu")

            dist.clear()

            countdown -= 1
            if exiting or countdown == 0:
                exit()



# Linux 4.15 introduced a new field runnable_weight
# in linux_src:kernel/sched/sched.h as
#     struct cfs_rq {
#         struct load_weight load;
#         unsigned long runnable_weight;
#         unsigned int nr_running, h_nr_running;
#         ......
#     }
# and this tool requires to access nr_running to get
# runqueue len information.
#
# The commit which introduces cfs_rq->runnable_weight
# field also introduces the field sched_entity->runnable_weight
# where sched_entity is defined in linux_src:include/linux/sched.h.
#
# To cope with pre-4.15 and 4.15/post-4.15 releases,
# we run a simple BPF program to detect whether
# field sched_entity->runnable_weight exists. The existence of
# this field should infer the existence of cfs_rq->runnable_weight.
#
# This will need maintenance as the relationship between these
# two fields may change in the future.
#
    def check_runnable_weight_field(self):

        # Get a temporary file name
        tmp_file = NamedTemporaryFile(delete=False)
        tmp_file.close();

        # Duplicate and close stderr (fd = 2)
        old_stderr = dup(2)
        close(2)

        # Open a new file, should get fd number 2
        # This will avoid printing llvm errors on the screen
        fd = open(tmp_file.name, O_WRONLY)
        try:
            t = BPF(text=self.bpf_check_text)
            success_compile = True
        except:
            success_compile = False

        # Release the fd 2, and next dup should restore old stderr
        close(fd)
        dup(old_stderr)
        close(old_stderr)

        # remove the temporary file and return
        unlink(tmp_file.name)
        return success_compile




def client_main(args):

    # arguments
    examples = """examples:
        ./runqlen            # summarize run queue length as a histogram
        ./runqlen 1 10       # print 1 second summaries, 10 times
        ./runqlen -T 1       # 1s summaries and timestamps
        ./runqlen -O         # report run queue occupancy
        ./runqlen -C         # show each CPU separately
    """
    parser = argparse.ArgumentParser(
        description="Summarize scheduler run queue length as a histogram",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-T", "--timestamp", action="store_true",
        help="include timestamp on output")
    parser.add_argument("-O", "--runqocc", action="store_true",
        help="report run queue occupancy")
    parser.add_argument("-C", "--cpus", action="store_true",
        help="print output for each CPU separately")
    parser.add_argument("interval", nargs="?", default=99999999,
        help="output interval, in seconds")
    parser.add_argument("count", nargs="?", default=99999999,
        help="number of outputs")
    parser.add_argument("--ebpf", action="store_true",
        help=argparse.SUPPRESS)
    parser.add_argument("-j", "--json", action="store_true",
                        help="output json objects")
    args = parser.parse_args()
    debug = 0
    frequency = 99

    probe = renqlen_sensor(args)

if __name__ == "__main__":
    import argparse, sys
    client_main(sys.argv)
    sys.exit(0)
