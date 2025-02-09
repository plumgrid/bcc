#!/usr/bin/env python

from unittest import main, skipUnless, TestCase
import distutils.version
import os
import sys
import atexit
import time
import subprocess
import threading
import socket

TOOLS_DIR = "../../tools/"



def kernel_version_ge(major, minor):
    # True if running kernel is >= X.Y
    version = distutils.version.LooseVersion(os.uname()[2]).version
    if version[0] > major:
        return True
    if version[0] < major:
        return False
    if minor and version[1] < minor:
        return False
    return True

def has_docker():
    try:
        version = subprocess.check_output(['docker', 'version', '-f',
                                           '{{.Client.Version}}']).strip().decode("utf-8")
        if distutils.version.LooseVersion(version) >= distutils.version.LooseVersion("18.09.9"):
            return True
        else:
            print("Incompatible docker version %s" % version)
            return False
    except FileNotFoundError:
        return False

def run_memcached():
    subprocess.check_output(['docker', 'run', '--name', 'memcached-dtrace',
                             '-p', '11211:11211/tcp',
                             'quay.io/dalehamel/memcached-dtrace:latest'])

def stop_memcached():
    try:
        subprocess.check_output(['docker', 'rm', '-f', 'memcached-dtrace'])
    except subprocess.CalledProcessError:
        return False

def wait_memcached():
    checks = 0
    running = "false"
    while running != "true" and checks < 10:
        time.sleep(1)
        try:
            running = subprocess.check_output(['docker', 'inspect', 'memcached-dtrace',
                                       '-f', '{{.State.Running}}']).strip().decode('utf-8')
        except subprocess.CalledProcessError:
            continue
# Needs a memcached instance to probe
def setUpModule():
    stop_memcached()
    thread = threading.Thread(target=run_memcached, args=())
    thread.daemon = True                            # Daemonize thread
    thread.start()
    wait_memcached()

@skipUnless(kernel_version_ge(4, 6), "requires kernel >= 4.6")
@skipUnless(has_docker(), "this test requires a container runtime like docker")
class MemleakToolTests(TestCase):
    #def tearDown(self):
    #    if self.p:
    #        del(self.p)

    # FIXME script getting output out of mctop
    def run_leaker(self, leak_kind):
        # Starting mctop.py
        cmd_format = ( 'stdbuf -o 0 -i 0 timeout -s KILL 10s ' + TOOLS_DIR + 'mctop.py -p %s')


        #self.p = subprocess.Popen(cmd_format.format(leak_kind),
        #                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        #                          shell=True)

        ## Waiting for the first report.
        #while True:
        #    self.p.poll()
        #    if self.p.returncode is not None:
        #        break
        #    line = self.p.stdout.readline()
        #    if b"with outstanding allocations" in line:
        #        break

        ## At this point, memleak.py have already launched application and set
        ## probes. Sending command to the leaking application to make its
        ## allocations.
        #out = self.p.communicate(input=b"\n")[0]

        ## If there were memory leaks, they are in the output. Filter the lines
        ## containing "byte" substring. Every interesting line is expected to
        ## start with "N bytes from"
        #x = [x for x in out.split(b'\n') if b'byte' in x]

        #self.assertTrue(len(x) >= 1,
        #                msg="At least one line should have 'byte' substring.")

        ## Taking last report.
        #x = x[-1].split()
        #self.assertTrue(len(x) >= 1,
        #                msg="There should be at least one word in the line.")

        ## First word is the leak amount in bytes.
        #return int(x[0])

    def send_command(self, msg):
        data = ""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect(('127.0.0.1', 11211))
            s.sendall(bytes(msg, 'utf-8'))
            data = s.recv(1024)
        return data

    def test_connect(self):
        reply = self.send_command("set memtier-35026400 0 60 4\r\ndata\r\n").strip().decode('utf-8')
        self.assertEqual(reply, 'STORED')

def cleanup():
    stop_memcached()
    timeout_sec = 5
    for p in all_processes: # list of your processes
        p_sec = 0
        for second in range(timeout_sec):
            if p.poll() == None:
                time.sleep(1)
                p_sec += 1
        if p_sec >= timeout_sec:
            p.kill() # supported from python 2.6
    print('cleaned up!')

if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup()
