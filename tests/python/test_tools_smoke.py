#!/usr/bin/env python3
# Copyright (c) Sasha Goldshtein, 2017
# Licensed under the Apache License, Version 2.0 (the "License")

import subprocess
import os
import re
from unittest import main, skipUnless, TestCase
from utils import mayFail, kernel_version_ge

TOOLS_DIR = "/bcc/tools/"

if not os.path.exists("/bcc/tools/"):
    TOOLS_DIR = "../../tools/"

def _helpful_rc_msg(rc, allow_early, kill):
    s = "rc was %d\n" % rc
    if rc == 0:
        s += "\tMeaning: command returned successfully before test timeout\n"
    elif rc == 124:
        s += "\tMeaning: command was killed by INT signal\n"
    elif rc == 137:
        s += "\tMeaning: command was killed by KILL signal\n"

    s += "Command was expected to do one of:\n"
    s += "\tBe killed by SIGINT\n"
    if kill:
        s += "\tBe killed by SIGKILL\n"
    if allow_early:
        s += "\tSuccessfully return before being killed\n"

    return s

@skipUnless(kernel_version_ge(4,1), "requires kernel >= 4.1")
class SmokeTests(TestCase):
    # Use this for commands that have a built-in timeout, so they only need
    # to be killed in case of a hard hang.
    def run_with_duration(self, command, timeout=10):
        full_command = TOOLS_DIR + command
        self.assertEqual(0,     # clean exit
                subprocess.call("timeout -s KILL %ds %s > /dev/null" %
                                (timeout, full_command), shell=True))

    # Use this for commands that don't have a built-in timeout, so we have
    # to Ctrl-C out of them by sending SIGINT. If that still doesn't stop
    # them, send a kill signal 5 seconds later.
    def run_with_int(self, command, timeout=5, kill_timeout=5,
                     allow_early=False, kill=False):
        full_command = TOOLS_DIR + command
        signal = "KILL" if kill else "INT"
        rc = subprocess.call("timeout -s %s -k %ds %ds %s > /dev/null" %
                (signal, kill_timeout, timeout, full_command), shell=True)
        # timeout returns 124 if the program did not terminate prematurely,
        # and returns 137 if we used KILL instead of INT. So there are three
        # sensible scenarios:
        #   1. The script is allowed to return early, and it did, with a
        #      success return code.
        #   2. The script timed out and was killed by the SIGINT signal.
        #   3. The script timed out and was killed by the SIGKILL signal, and
        #      this was what we asked for using kill=True.
        self.assertTrue((rc == 0 and allow_early) or rc == 124
                        or (rc == 137 and kill), _helpful_rc_msg(rc,
                        allow_early, kill))

    def kmod_loaded(self, mod):
        with open("/proc/modules", "r") as mods:
            reg = re.compile(r'^%s\s' % mod)
            for line in mods:
                if reg.match(line):
                    return 1
                return 0

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_argdist(self):
        self.run_with_duration("argdist.py -v -C 'p::do_sys_open()' -n 1 -i 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_bashreadline(self):
        self.run_with_int("bashreadline.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_bindsnoop(self):
        self.run_with_int("bindsnoop.py")

    def test_biolatency(self):
        self.run_with_duration("biolatency.py 1 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_biosnoop(self):
        self.run_with_int("biosnoop.py")

    def test_biotop(self):
        self.run_with_duration("biotop.py 1 1")

    def test_bitesize(self):
        self.run_with_int("biotop.py")

    def test_bpflist(self):
        self.run_with_duration("bpflist.py")

    def test_btrfsdist(self):
        # Will attempt to do anything meaningful only when btrfs is installed.
        self.run_with_duration("btrfsdist.py 1 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_btrfsslower(self):
        # Will attempt to do anything meaningful only when btrfs is installed.
        self.run_with_int("btrfsslower.py", allow_early=True)

    def test_cachestat(self):
        self.run_with_duration("cachestat.py 1 1")

    def test_cachetop(self):
        # TODO cachetop doesn't like to run without a terminal, disabled
        # for now.
        # self.run_with_int("cachetop.py 1")
        pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_capable(self):
        self.run_with_int("capable.py")

    def test_cpudist(self):
        self.run_with_duration("cpudist.py 1 1")

    @skipUnless(kernel_version_ge(4,9), "requires kernel >= 4.9")
    def test_cpuunclaimed(self):
        self.run_with_duration("cpuunclaimed.py 1 1")

    @skipUnless(kernel_version_ge(4,17), "requires kernel >= 4.17")
    def test_compactsnoop(self):
        self.run_with_int("compactsnoop.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_dbslower(self):
        # Deliberately left empty -- dbslower requires an instance of either
        # MySQL or PostgreSQL to be running, or it fails to attach.
        pass

    @skipUnless(kernel_version_ge(4,3), "requires kernel >= 4.3")
    def test_dbstat(self):
        # Deliberately left empty -- dbstat requires an instance of either
        # MySQL or PostgreSQL to be running, or it fails to attach.
        pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_dcsnoop(self):
        self.run_with_int("dcsnoop.py")

    def test_dcstat(self):
        self.run_with_duration("dcstat.py 1 1")

    @skipUnless(kernel_version_ge(4,6), "requires kernel >= 4.6")
    def test_deadlock(self):
        # TODO This tool requires a massive BPF stack traces table allocation,
        # which might fail the run or even trigger the oomkiller to kill some
        # other processes. Disabling for now.
        # self.run_with_int("deadlock.py $(pgrep -n bash)", timeout=10)
        pass

    @skipUnless(kernel_version_ge(4,7), "requires kernel >= 4.7")
    def test_drsnoop(self):
        self.run_with_int("drsnoop.py")

    @skipUnless(kernel_version_ge(4,8), "requires kernel >= 4.8")
    def test_execsnoop(self):
        self.run_with_int("execsnoop.py")

    def test_ext4dist(self):
        self.run_with_duration("ext4dist.py 1 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_ext4slower(self):
        self.run_with_int("ext4slower.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_f2fsslower(self):
        self.run_with_int("f2fsslower.py", allow_early=True)

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_filelife(self):
        self.run_with_int("filelife.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_fileslower(self):
        self.run_with_int("fileslower.py")

    def test_filetop(self):
        self.run_with_duration("filetop.py 1 1")

    def test_funccount(self):
        self.run_with_int("funccount.py __kmalloc -i 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_funclatency(self):
        self.run_with_int("funclatency.py __kmalloc -i 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_funcslower(self):
        self.run_with_int("funcslower.py __kmalloc")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_gethostlatency(self):
        self.run_with_int("gethostlatency.py")

    @skipUnless(kernel_version_ge(4,7), "requires kernel >= 4.7")
    def test_hardirqs(self):
        self.run_with_duration("hardirqs.py 1 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_killsnoop(self):
        # Because killsnoop intercepts signals, if we send it a SIGINT we we
        # we likely catch it while it is handling the data packet from the
        # BPF program, and the exception from the SIGINT will be swallowed by
        # ctypes. Therefore, we use SIGKILL.
        # To reproduce the above issue, run killsnoop and in another shell run
        # `kill -s SIGINT $(pidof python)`. As a result, killsnoop will print
        # a traceback but will not exit.
        self.run_with_int("killsnoop.py", kill=True)

    @skipUnless(kernel_version_ge(4,18), "requires kernel >= 4.18")
    def test_klockstat(self):
        self.run_with_int("klockstat.py")

    @skipUnless(kernel_version_ge(4,9), "requires kernel >= 4.9")
    def test_llcstat(self):
        # Requires PMU, which is not available in virtual machines.
        pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_mdflush(self):
        self.run_with_int("mdflush.py")

    @skipUnless(kernel_version_ge(4,6), "requires kernel >= 4.6")
    def test_memleak(self):
        self.run_with_duration("memleak.py 1 1")

    @skipUnless(kernel_version_ge(4,8), "requires kernel >= 4.8")
    def test_mountsnoop(self):
        self.run_with_int("mountsnoop.py")

    @skipUnless(kernel_version_ge(4,3), "requires kernel >= 4.3")
    def test_mysqld_qslower(self):
        # Deliberately left empty -- mysqld_qslower requires an instance of
        # MySQL to be running, or it fails to attach.
        pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_nfsslower(self):
        if(self.kmod_loaded("nfs")):
            self.run_with_int("nfsslower.py")
        else:
            pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_nfsdist(self):
        if(self.kmod_loaded("nfs")):
            self.run_with_duration("nfsdist.py 1 1")
        else:
            pass

    @skipUnless(kernel_version_ge(4,6), "requires kernel >= 4.6")
    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_offcputime(self):
        self.run_with_duration("offcputime.py 1")

    @skipUnless(kernel_version_ge(4,6), "requires kernel >= 4.6")
    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_offwaketime(self):
        self.run_with_duration("offwaketime.py 2", timeout=30)

    @skipUnless(kernel_version_ge(4,9), "requires kernel >= 4.9")
    def test_oomkill(self):
        self.run_with_int("oomkill.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_opensnoop(self):
        self.run_with_int("opensnoop.py")

    def test_pidpersec(self):
        self.run_with_int("pidpersec.py")

    @skipUnless(kernel_version_ge(4,17), "requires kernel >= 4.17")
    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_syscount(self):
        self.run_with_int("ppchcalls.py -i 1")

    @skipUnless(kernel_version_ge(4,9), "requires kernel >= 4.9")
    def test_profile(self):
        self.run_with_duration("profile.py 1")

    def test_runqlat(self):
        self.run_with_duration("runqlat.py 1 1")

    @skipUnless(kernel_version_ge(4,9), "requires kernel >= 4.9")
    def test_runqlen(self):
        self.run_with_duration("runqlen.py 1 1")

    @skipUnless(kernel_version_ge(4,8), "requires kernel >= 4.8")
    def test_shmsnoop(self):
        self.run_with_int("shmsnoop.py")

    @skipUnless(kernel_version_ge(4,8), "requires kernel >= 4.8")
    def test_sofdsnoop(self):
        self.run_with_int("sofdsnoop.py")

    def test_slabratetop(self):
        self.run_with_duration("slabratetop.py 1 1")

    @skipUnless(kernel_version_ge(4,7), "requires kernel >= 4.7")
    def test_softirqs(self):
        self.run_with_duration("softirqs.py 1 1")
        pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_solisten(self):
        self.run_with_int("solisten.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_sslsniff(self):
        self.run_with_int("sslsniff.py --no-nss")

    @skipUnless(kernel_version_ge(4,6), "requires kernel >= 4.6")
    def test_stackcount(self):
        self.run_with_int("stackcount.py __kmalloc -i 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_statsnoop(self):
        self.run_with_int("statsnoop.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_syncsnoop(self):
        self.run_with_int("syncsnoop.py")

    @skipUnless(kernel_version_ge(4,7), "requires kernel >= 4.7")
    def test_syscount(self):
        self.run_with_int("syscount.py -i 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_tcpaccept(self):
        self.run_with_int("tcpaccept.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_tcpconnect(self):
        self.run_with_int("tcpconnect.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_tcpconnlat(self):
        self.run_with_int("tcpconnlat.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_tcplife(self):
        self.run_with_int("tcplife.py")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_tcpretrans(self):
        self.run_with_int("tcpretrans.py")

    @skipUnless(kernel_version_ge(4, 7), "requires kernel >= 4.7")
    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_tcpdrop(self):
        self.run_with_int("tcpdrop.py")

    def test_tcptop(self):
        self.run_with_duration("tcptop.py 1 1")

    def test_tcpcong(self):
        self.run_with_duration("tcpcong.py 1 1")

    def test_tplist(self):
        self.run_with_duration("tplist.py -p %d" % os.getpid())

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_trace(self):
        self.run_with_int("trace.py do_sys_open")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_ttysnoop(self):
        self.run_with_int("ttysnoop.py /dev/console")

    @skipUnless(kernel_version_ge(4,7), "requires kernel >= 4.7")
    def test_ucalls(self):
        self.run_with_int("lib/ucalls.py -l none -S %d" % os.getpid())

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_uflow(self):
        # The Python installed on the Ubuntu buildbot doesn't have USDT
        # probes, so we can't run uflow.
        # self.run_with_int("pythonflow.py %d" % os.getpid())
        pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_ugc(self):
        # This requires a runtime that has GC probes to be installed.
        # Python has them, but only in very recent versions. Skip.
        pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_uobjnew(self):
        self.run_with_int("cobjnew.sh %d" % os.getpid())

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_ustat(self):
        self.run_with_duration("lib/ustat.py 1 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_uthreads(self):
        self.run_with_int("lib/uthreads.py %d" % os.getpid())

    def test_vfscount(self):
        self.run_with_int("vfscount.py", timeout=15, kill_timeout=15)

    def test_vfsstat(self):
        self.run_with_duration("vfsstat.py 1 1")

    @skipUnless(kernel_version_ge(4,6), "requires kernel >= 4.6")
    def test_wakeuptime(self):
        self.run_with_duration("wakeuptime.py 1")

    @skipUnless(kernel_version_ge(4,7), "requires kernel >= 4.7")
    def test_wqlat(self):
        self.run_with_int("wqlat.py 1 1", allow_early=True)

    def test_xfsdist(self):
        # Doesn't work on build bot because xfs functions not present in the
        # kernel image.
        # self.run_with_duration("xfsdist.py 1 1")
        pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_xfsslower(self):
        # Doesn't work on build bot because xfs functions not present in the
        # kernel image.
        # self.run_with_int("xfsslower.py")
        pass

    def test_zfsdist(self):
        # Fails to attach the probe if zfs is not installed.
        pass

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_zfsslower(self):
        # Fails to attach the probe if zfs is not installed.
        pass

if __name__ == "__main__":
    main()
