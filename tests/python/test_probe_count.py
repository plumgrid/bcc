#!/usr/bin/env python
# Copyright (c) Suchakra Sharma <suchakrapani.sharma@polymtl.ca>
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF, _get_num_open_probes
import os
import sys
from unittest import main, TestCase

class TestKprobeCnt(TestCase):
    def setUp(self):
        self.b = BPF(text="""
        int wololo(void *ctx) {
          return 0;
        }
        """)
        self.b.attach_kprobe(event_re="^vfs_.*", fn_name="wololo")

    def test_attach1(self):
        actual_cnt = 0
        with open("/sys/kernel/debug/tracing/available_filter_functions") as f:
            for line in f:
                if str(line).startswith("vfs_"):
                    actual_cnt += 1
        open_cnt = self.b.num_open_kprobes()
        self.assertEqual(actual_cnt, open_cnt)

    def tearDown(self):
        self.b.cleanup()


class TestProbeGlobalCnt(TestCase):
    def setUp(self):
        self.b1 = BPF(text="""int count(void *ctx) { return 0; }""")
        self.b2 = BPF(text="""int count(void *ctx) { return 0; }""")

    def test_probe_quota(self):
        self.b1.attach_kprobe(event="schedule", fn_name="count")
        self.b2.attach_kprobe(event="submit_bio", fn_name="count")
        self.assertEqual(1, self.b1.num_open_kprobes())
        self.assertEqual(1, self.b2.num_open_kprobes())
        self.assertEqual(2, _get_num_open_probes())
        self.b1.cleanup()
        self.b2.cleanup()
        self.assertEqual(0, _get_num_open_probes())


class TestAutoKprobe(TestCase):
    def setUp(self):
        self.b = BPF(text="""
        int kprobe__schedule(void *ctx) { return 0; }
        int kretprobe__schedule(void *ctx) { return 0; }
        """)

    def test_count(self):
        self.assertEqual(2, self.b.num_open_kprobes())

    def tearDown(self):
        self.b.cleanup()


class TestProbeQuota(TestCase):
    def setUp(self):
        self.b = BPF(text="""int count(void *ctx) { return 0; }""")

    def test_probe_quota(self):
        with self.assertRaises(Exception):
            self.b.attach_kprobe(event_re=".*", fn_name="count")

    def test_uprobe_quota(self):
        with self.assertRaises(Exception):
            self.b.attach_uprobe(name="c", sym_re=".*", fn_name="count")

    def tearDown(self):
        self.b.cleanup()

class TestProbeInstance(TestCase):
    def setUp(self):
        self.b = BPF(text="""int count(void *ctx) { return 0; }""")

    def test_kprobe_instance(self):
        instance = "/sys/kernel/debug/tracing/instances/bcc_{}".format(
            os.getpid())
        self.assertFalse(os.path.isdir(instance))

        self.b.attach_kprobe(event="sys_read", fn_name="count")
        inode = os.stat(instance).st_ino
        self.assertTrue(inode > 1)

        self.b.attach_kprobe(event="sys_write", fn_name="count")
        self.b.detach_kprobe("sys_read")
        new_inode = os.stat(instance).st_ino
        self.assertEqual(new_inode, inode)

        self.b.detach_kprobe("sys_write")
        self.assertFalse(os.path.isdir(instance))

        self.b.attach_kprobe(event="sys_open", fn_name="count")
        new_inode = os.stat(instance).st_ino
        self.assertTrue(new_inode > 1)
        self.assertFalse(new_inode == inode)


class TestProbeNotExist(TestCase):
    def setUp(self):
        self.b = BPF(text="""int count(void *ctx) { return 0; }""")

    def test_not_exist(self):
        with self.assertRaises(Exception):
            b.attach_kprobe(event="___doesnotexist", fn_name="count")

    def tearDown(self):
        self.b.cleanup()


if __name__ == "__main__":
    main()
