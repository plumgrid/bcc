#!/usr/bin/env python3
#
# USAGE: test_usdt.py
#
# Copyright 2017 Facebook, Inc
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF, USDT
from unittest import main, TestCase, skipUnless

from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile
from utils import kernel_version_ge
import ctypes as ct
import inspect
import os
import signal

class TestUDST(TestCase):
    def setUp(self):
        # Application, minimum, to define three trace points
        app_text = b"""
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "folly/tracing/StaticTracepoint.h"

FOLLY_SDT_DEFINE_SEMAPHORE(test, probe_point_1)
int main() {
  char s[100];
  int i, a = 200, b = 40;
  for (i = 0; i < 100; i++) s[i] = (i & 7) + (i & 6);
  uint64_t j = 0;
  char s1[64];
  const char* str = "str";
  size_t len = strlen(str);
  while (1) {
    FOLLY_SDT_WITH_SEMAPHORE(test, probe_point_1, s[7], b);
    FOLLY_SDT(test, probe_point_3, a, b);
    FOLLY_SDT(test, probe_point_1, s[4], a);
    FOLLY_SDT(test, probe_point_2, 5, s[10]);
    FOLLY_SDT(test, probe_point_3, s[4], s[7]);

    memset(&s1, '\0', sizeof(s1));
    strncpy(s1, str, len);
    snprintf(s1 + len, sizeof(s1) - len, "%d", j);
    FOLLY_SDT(test, probe_point_4, j++, &s1);

    memset(&s1, '\0', sizeof(s1));
    strncpy(s1, str, len);
    snprintf(s1 + len, sizeof(s1) - len, "%d", j);
    FOLLY_SDT(test, probe_point_5, &s1, j++);

    sleep(1);
  }
  return 1;
}
"""
        # BPF program
        self.bpf_text = b"""
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>

struct probe_result_t1 {
  char v1;
  int  v2;
};

struct probe_result_t2 {
  int  v1;
  char v2;
};

struct probe_result_t3 {
  int v1;
  int v2;
};

struct probe_result_t4 {
  u64  v1;
  char v2[8];
};

struct probe_result_t5 {
  char v1[8];
  u64  v2;
};

BPF_PERF_OUTPUT(event1);
BPF_PERF_OUTPUT(event2);
BPF_PERF_OUTPUT(event3);
BPF_PERF_OUTPUT(event4);
BPF_PERF_OUTPUT(event5);

int do_trace1(struct pt_regs *ctx) {
    struct probe_result_t1 result = {};
    bpf_usdt_readarg(1, ctx, &result.v1);
    bpf_usdt_readarg(2, ctx, &result.v2);
    event1.perf_submit(ctx, &result, sizeof(result));
    return 0;
};
int do_trace2(struct pt_regs *ctx) {
    struct probe_result_t2 result = {};
    bpf_usdt_readarg(1, ctx, &result.v1);
    bpf_usdt_readarg(2, ctx, &result.v2);
    event2.perf_submit(ctx, &result, sizeof(result));
    return 0;
}
int do_trace3(struct pt_regs *ctx) {
    struct probe_result_t3 result = {};
    bpf_usdt_readarg(1, ctx, &result.v1);
    bpf_usdt_readarg(2, ctx, &result.v2);
    event3.perf_submit(ctx, &result, sizeof(result));
    return 0;
}
int do_trace4(struct pt_regs *ctx) {
    struct probe_result_t4 result = {};
    bpf_usdt_readarg(1, ctx, &result.v1);
    bpf_usdt_readarg_p(2, ctx, &result.v2, sizeof(result.v2));
    event4.perf_submit(ctx, &result, sizeof(result));
    return 0;
}
int do_trace5(struct pt_regs *ctx) {
    struct probe_result_t5 result = {};
    bpf_usdt_readarg_p(1, ctx, &result.v1, sizeof(result.v1));
    bpf_usdt_readarg(2, ctx, &result.v2);
    event5.perf_submit(ctx, &result, sizeof(result));
    return 0;
}
"""

        # Compile and run the application
        self.ftemp = NamedTemporaryFile(delete=False)
        self.ftemp.close()
        comp = Popen(["gcc", "-I", "%s/include" % os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))),
                      "-x", "c++", "-o", self.ftemp.name, "-"],
                     stdin=PIPE)
        comp.stdin.write(app_text)
        comp.stdin.close()
        self.assertEqual(comp.wait(), 0)
        self.app = Popen([self.ftemp.name])

    @skipUnless(kernel_version_ge(4,20), "requires kernel >= 4.20")
    def test_attach_path(self):
        u = USDT(path=self.ftemp.name)
        # This will (should not) fail with bcc.usdt.USDTException: Failed to enable USDT probe, fix in the way
        u.enable_probe(probe="probe_point_1", fn_name="do_trace1")

    def test_attach1(self):
        # enable USDT probe from given PID and verifier generated BPF programs
        u = USDT(pid=int(self.app.pid))
        u.enable_probe(probe="probe_point_1", fn_name="do_trace1")
        u.enable_probe(probe="probe_point_2", fn_name="do_trace2")
        u.enable_probe(probe="probe_point_3", fn_name="do_trace3")
        u.enable_probe(probe="probe_point_4", fn_name="do_trace4")
        u.enable_probe(probe="probe_point_5", fn_name="do_trace5")
        b = BPF(text=self.bpf_text, usdt_contexts=[u], debug=4)

        # Event states for each event:
        # 0 - probe not caught, 1 - probe caught with correct value,
        # 2 - probe caught with incorrect value
        self.evt_st_1 = 0
        self.evt_st_2 = 0
        self.evt_st_3 = 0

        # define output data structure in Python
        class Data1(ct.Structure):
            _fields_ = [("v1", ct.c_char),
                        ("v2", ct.c_int)]

        class Data2(ct.Structure):
            _fields_ = [("v1", ct.c_int),
                        ("v2", ct.c_char)]

        class Data3(ct.Structure):
            _fields_ = [("v1", ct.c_int),
                        ("v2", ct.c_int)]

        class Data4(ct.Structure):
            _fields_ = [("v1", ct.c_ulonglong),
                        ("v2", ct.c_char * 64)]

        class Data5(ct.Structure):
            _fields_ = [("v1", ct.c_char * 64),
                        ("v2", ct.c_ulonglong)]

        def check_event_val(event, event_state, v1, v2, v3, v4):
            if ((event.v1 == v1 and event.v2 == v2) or (event.v1 == v3 and event.v2 == v4)):
                if (event_state == 0 or event_state == 1):
                    return 1
            return 2

        def print_event1(cpu, data, size):
            event = ct.cast(data, ct.POINTER(Data1)).contents
            self.evt_st_1 = check_event_val(event, self.evt_st_1, b'\x0d', 40, b'\x08', 200)

        def print_event2(cpu, data, size):
            event = ct.cast(data, ct.POINTER(Data2)).contents
            # pretend we have two identical probe points to simplify the code
            self.evt_st_2 = check_event_val(event, self.evt_st_2, 5, b'\x04', 5, b'\x04')

        def print_event3(cpu, data, size):
            event = ct.cast(data, ct.POINTER(Data3)).contents
            self.evt_st_3 = check_event_val(event, self.evt_st_3, 200, 40, 8, 13)

        def print_event4(cpu, data, size):
            event = ct.cast(data, ct.POINTER(Data4)).contents
            print("%s" % event.v2)

        def print_event5(cpu, data, size):
            event = ct.cast(data, ct.POINTER(Data5)).contents
            print("%s" % event.v1)

        # loop with callback to print_event
        b[b"event1"].open_perf_buffer(print_event1)
        b[b"event2"].open_perf_buffer(print_event2)
        b[b"event3"].open_perf_buffer(print_event3)
        b[b"event4"].open_perf_buffer(print_event4)
        b[b"event5"].open_perf_buffer(print_event5)

        # three iterations to make sure we get some probes and have time to process them
        for i in range(3):
            b.perf_buffer_poll()
        self.assertTrue(self.evt_st_1 == 1 and self.evt_st_2 == 1 and self.evt_st_3 == 1)

    def tearDown(self):
        # kill the subprocess, clean the environment
        self.app.kill()
        self.app.wait()
        os.unlink(self.ftemp.name)

if __name__ == "__main__":
    main()
