# Copyright 2017 Joel Fernandes <joelaf@google.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import pexpect as pe

from . import remote_utils
from .base import BccRemote

class ShellRemote(BccRemote):
    def __init__(self, cmd=None):
        """
        Create a local connection by spawning bpfd and communicating
        with it using the spawned bpfd process's stdin and stdout.

        :param cmd: Command to execute for bpfd. If not specified,
                    then we default to search for bpfd in the path.
        :type cmd: str
        """
        if cmd == None:
            cmd = 'bpfd'

        self.client = pe.spawn(cmd, echo=False, timeout=None)
        self.client.expect('STARTED_BPFD')

    def send_command(self, cmd):
        remote_utils.log('Sending command {}'.format(cmd))

        c = self.client
        raise_interrupt = False

        try:
            c.sendline(cmd)
        except KeyboardInterrupt:
            # raise a SystemExit exception so the interpreter can call the proper
            # BPF module atexit.register(self.cleanup) and not spew a traceback
            # Important: do not kill the pexpect child here so the cleanup can be done
            sys.exit(0)

        while c.isalive():
            try:
                c.expect('END_BPFD_OUTPUT')
                break
            except pe.exceptions.EOF:
                return [b'Command not recognized (timeout)']
            except KeyboardInterrupt:
                # stop any blocking perf reader polls before triggering exit cleanups
                c.sendline()
                raise_interrupt = True

        if raise_interrupt:
            sys.exit(0)

        ret = c.before.split(b'\n')

        # Sanitize command output
        ret = [r.rstrip() for r in ret if r]

        i = 0
        while (ret[i].startswith(b'START_BPFD_OUTPUT') != True):
            i = i + 1

        remote_utils.log('Received {}'.format(ret[(i+1):][:50]))

        return ret[(i+1):]

    def send_exit_command(self):
        remote_utils.log('Sending command exit')

        self.client.sendline('exit')

        remote_utils.log('Success: bpfd terminated')

    def close_connection(self):
        self.send_exit_command()
        self.client.close(force=True)

