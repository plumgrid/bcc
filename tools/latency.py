#!/usr/bin/python
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2020 hongzhi-yang.
# python latency.py -i 1 -C "${BIN_PATH}:0x228e811-0x228eff7:latency>16384" -v -n 1 -p 124

from bcc import BPF, USDT
import ctypes as ct
from time import sleep, strftime
import argparse
import re
import traceback
import os
import sys

lib = ct.CDLL("libbcc.so.0", use_errno=True)
_SYM_CB_TYPE = ct.CFUNCTYPE(ct.c_int, ct.c_char_p, ct.c_ulonglong)

def start_func_info(binary_path, start, end):
    assert start < end, "start must > end"

    start_addr_max = ["", -1]
    end_addr_max = ["", -1]
    def sym_cb(sym_name, addr):
        if addr < start and start_addr_max[1] < addr:
            start_addr_max[0] = sym_name
            start_addr_max[1] = addr
        if addr < end and end_addr_max[1] < addr:
            end_addr_max[0] = sym_name
            end_addr_max[1] = addr
        return 0
    res = lib.bcc_foreach_function_symbol(binary_path, _SYM_CB_TYPE(sym_cb))
    assert res >= 0, "Error %d enumerating symbols in %s" % (res, binary_path)

    assert start_addr_max[1] == end_addr_max[1], "start end must belongs to same func"
    return start_addr_max

def func_addr_offset(binary_path, func, func_addr, pid):
    (binary_path, bind_addr) = BPF._check_path_symbol(binary_path, func, func_addr, pid)
    return binary_path, (func_addr - bind_addr)

def specifier_format(specifier):
    specifier_spans = specifier.split(":")
    assert len(specifier_spans) in {2, 3}

    start_addr = 0
    end_addr = 0
    try:
        addr_s = specifier_spans[1].split("-")
        start_addr = int(addr_s[0],16)
        end_addr = int(addr_s[1], 16)
    except:
        raise ValueError("second field format must be %s".format("0x120-0x130"))

    specifier_info = {
        "binary_path":specifier_spans[0],
        "start_addr":start_addr,
        "end_addr":end_addr,
        "latency_span":""
    }
    if (len(specifier_spans) == 3):
        specifier_info["latency_span"] = specifier_spans[2].replace("latency", "")

    return specifier_info

class Probe(object):
    bpf_start = """
        #include <uapi/linux/ptrace.h>           
            
        BPF_HASH(__latency, u32, u64);
        int __probe_start(struct pt_regs *ctx )
        {
            u64 __pid_tgid = bpf_get_current_pid_tgid();
            u32 __pid      = __pid_tgid;    // lower 32 bits
            u32 __tgid     = __pid_tgid >> 32;  // upper 32 bits

            PID_FILTER
                
            u64 __time = bpf_ktime_get_ns();
            __latency.update(&__pid, &__time);
            return 0;
        }

        int __probe_free(struct pt_regs *ctx){
            u64 __pid_tgid = bpf_get_current_pid_tgid();
            u32 __pid      = __pid_tgid;    // lower 32 bits
                
            __latency.delete(&__pid);
            return 0;
        }
        """

    bpf_end_histogram = """
        BPF_HISTOGRAM(_hash_res, unsigned int);
        int __probe_end(struct pt_regs *ctx )
        {
            u64 __pid_tgid = bpf_get_current_pid_tgid();
            u32 __pid      = __pid_tgid;    // lower 32 bits
                
            u64 *____start_time = __latency.lookup(&__pid);
            if (____start_time == 0) { return 0 ; }

            LATENCY_VALUE
            LATENCY_FILTER
            _hash_res.increment(bpf_log2l(__latency_value));
            return 0;
        }
        """

    bpf_end_count= """
        struct _hash_res_key_t {
            u32 v0;
        };
        BPF_HASH(_hash_res, struct _hash_res_key_t, u64);
        int __probe_end(struct pt_regs *ctx )
        {
            u64 __pid_tgid = bpf_get_current_pid_tgid();
            u32 __pid      = __pid_tgid;    // lower 32 bits
               
            u64 *____start_time = __latency.lookup(&__pid);
            if (____start_time == 0) { return 0 ; }

            LATENCY_VALUE
            LATENCY_FILTER

            struct _hash_res_key_t __key = {};
            __key.v0 = __latency_value;
            _hash_res.increment(__key);
            return 0;
        }
        """

    def __init__(self, args, latency_span):
        pid_filter_code = "if (__tgid != %d) { return 0; }" % args.pid if args.pid > 0 else ""
        bpf_source = self.bpf_start.replace("PID_FILTER", pid_filter_code)

        if (args.histogram):
            bpf_source = bpf_source + self.bpf_end_histogram
        else:
            bpf_source = bpf_source + self.bpf_end_count

        latency_filter_code = "if (__latency_value %s){return 0;}" % latency_span if latency_span else ""
        bpf_source = bpf_source.replace("LATENCY_FILTER", latency_filter_code)

        latency_value_code = "unsigned int __latency_value = ((bpf_ktime_get_ns() - *____start_time)) / %d;"
        latency_value_code = latency_value_code % {
            "s":1000000000,
            "ms":1000000,
            "us":1000,
            "ns":1,
        }[args.unit]
        bpf_source = bpf_source.replace("LATENCY_VALUE", latency_value_code)

        self.bpf = BPF(text=bpf_source)
    
    def attach(self, path, addr, fn_name, pid):
        fn = self.bpf.load_func(fn_name, BPF.KPROBE)
        ev_name = self.bpf._get_uprobe_evname(b"p", path, addr, pid)
        fd = lib.bpf_attach_uprobe(fn.fd, 0, ev_name, path, addr, pid)
        assert fd > 0, "Failed to attach BPF to uprobe"

        self.bpf._add_uprobe_fd(ev_name, fd)

    def attach_ret(self, path, addr, fn_name, pid):
        fn = self.bpf.load_func(fn_name, BPF.KPROBE)
        ev_name = self.bpf._get_uprobe_evname(b"r", path, addr, pid)
        fd = lib.bpf_attach_uprobe(fn.fd, 1, ev_name, path, addr, pid)
        assert fd > 0, "Failed to attach BPF to uretprobe"

        self.bpf._add_uprobe_fd(ev_name, fd)

    def display_histogram(self, unit, clear_old=False):
        data = self.bpf.get_table("_hash_res")
        data.print_log2_hist(val_type="run latency (%s)" % unit)
        if (clear_old):
            data.clear()

    def display_call_count(self, unit, top=None, clear_old=False):
        data = self.bpf.get_table("_hash_res")
        print("run latency (%s)" % unit)
        print("\t%-10s %s" % ("COUNT", "LATENCY"))
        sdata = sorted(data.items(), key=lambda p: p[1].value)
        if top is not None:
            sdata = sdata[-top:]
        for key, value in sdata:
            print("\t%-10s %s" % (str(value.value), str(key.v0)))
        if (clear_old):
            data.clear()

class Tool(object):
    examples = """
Probe specifier syntax:
        library:start_addr-end_addr[:filter]
Where:
        library    -- the library that contains the function
                      (leave empty for kernel functions)
        start_addr -- the start of address to collect
                      (get addr by object/gdb ...)
        end_addr   -- the end of address to collect
        filter     -- expr such as (latency>100  latench<1000)

EXAMPLES:

./latency.py -H "/home/vagrant/a.out:660-667" -i 10 -p 1005
        Print a histogram of latency between 660-667 of a.out's assembly codes in process 1005
./latency.py -C "/home/vagrant/a.out:660-667" -i 10 -u ms
        Print frequency of latency(ms) between 660-667 of a.out's assembly codes
./latency.py -H "/home/vagrant/a.out:660-667:latency>101000000" -i 10 -u ns
        Print a histogram of latency(ns) between 660-667 of a.out's assembly codes
"""

    def __init__(self):
        parser = argparse.ArgumentParser(description="",
          formatter_class=argparse.RawDescriptionHelpFormatter,
          epilog=Tool.examples)
        parser.add_argument("-p", "--pid", type=int, default=-1,
          help="id of the process to trace (optional)")
          
        parser.add_argument("-H", "--histogram", default = "",
          help="probe specifier to capture histogram of " +
          "(see examples below)")
        parser.add_argument("-T", "--top", type=int,
          help="number of top results to show (not applicable to histograms)")
        parser.add_argument("-C", "--count", default = "",
          help="probe specifier to capture count of (see examples below)")

        parser.add_argument("-c", "--cumulative", action="store_true",
          help="do not clear histograms and freq counts at each interval")
        parser.add_argument("-i", "--interval", default=1, type=int,
          help="output interval, in seconds (default 1 second)")
        parser.add_argument("-d", "--duration", type=int,
          help="total duration of trace, in seconds")
        parser.add_argument("-n", "--number", type=int, help="number of outputs")
        parser.add_argument("-u", "--unit", type=str, default="ms", choices=["s", "ms", "us", "ns"],
          help="the unit of latency: s/ms/us/ns")

        parser.add_argument("-v", "--verbose", action="store_true",
          help="print resulting BPF program code before executing")
        
        self.args = parser.parse_args()
        if len(self.args.histogram) != 0:
            assert len(self.args.count)==0, "histogram | count must set one"
            assert self.args.top <= 0, "histogram no need top"
            self.specifier = self.args.histogram
        elif len(self.args.count) != 0:
            self.specifier = self.args.count
        else:
            raise ValueError("histogram | count must set one")

        self._bpf_attach()

    def _bpf_attach(self):
        specifier_info = specifier_format(self.specifier)

        t = start_func_info(specifier_info["binary_path"], specifier_info["start_addr"], specifier_info["end_addr"])
        (path, offset) = func_addr_offset(specifier_info["binary_path"], t[0], t[1], self.args.pid)
        
        self.probe = Probe(self.args, specifier_info["latency_span"])
        self.probe.attach(path, specifier_info["start_addr"]-offset, "__probe_start", self.args.pid)
        self.probe.attach(path, specifier_info["end_addr"]-offset, "__probe_end", self.args.pid)
        self.probe.attach_ret(path, t[1]-offset, "__probe_free", self.args.pid) 

    def _display(self):
        print("[%s]" % strftime("%H:%M:%S"))
        if (self.args.histogram):
               self.probe.display_histogram(self.args.unit, self.args.cumulative)
        else:
               self.probe.display_call_count(self.args.unit, self.args.top, self.args.cumulative)

    def latency_loop(self):
        count_so_far = 0
        seconds = 0
        while True:
            try:
                sleep(self.args.interval)
                seconds += self.args.interval
            except KeyboardInterrupt:
                exit()
            
            self._display()

            count_so_far += 1
            if self.args.number is not None and count_so_far >= self.args.number:
                exit()
            if self.args.duration and seconds >= self.args.duration:
                exit()

if __name__ == "__main__":
    Tool().latency_loop()

