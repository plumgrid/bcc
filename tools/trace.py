#!/usr/bin/env python
#
# trace         Trace a function and print a trace message based on its
#               parameters, with an optional filter.
#
# usage: trace [-h] [-p PID] [-L TID] [-v] [-Z STRING_SIZE] [-S] [-c cgroup_path]
#              [-M MAX_EVENTS] [-s SYMBOLFILES] [-T] [-t] [-K] [-U] [-a] [-I header]
#              [-A]
#              probe [probe ...]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from __future__ import print_function
from bcc import BPF, USDT, StrcmpRewrite
from functools import partial
from time import strftime
import time
import argparse
import re
import ctypes as ct
import os
import traceback
import sys

class Probe(object):
        probe_count = 0
        streq_index = 0
        max_events = None
        event_count = 0
        first_ts = 0
        first_ts_real = None
        print_time = False
        print_unix_timestamp = False
        use_localtime = True
        time_field = False
        print_cpu = False
        print_address = False
        tgid = -1
        pid = -1
        uid = -1
        page_cnt = None
        build_id_enabled = False
        aggregate = False
        symcount = {}
        done = False

        @classmethod
        def configure(cls, args):
                cls.max_events = args.max_events
                cls.print_time = args.timestamp or args.time
                cls.print_unix_timestamp = args.unix_timestamp
                cls.use_localtime = not args.timestamp
                cls.time_field = cls.print_time and (not cls.use_localtime)
                cls.print_cpu = args.print_cpu
                cls.print_address = args.address
                cls.first_ts = BPF.monotonic_time()
                cls.first_ts_real = time.time()
                cls.tgid = args.tgid or -1
                cls.pid = args.pid or -1
                cls.uid = args.uid or -1
                cls.page_cnt = args.buffer_pages
                cls.bin_cmp = args.bin_cmp
                cls.build_id_enabled = args.sym_file_list is not None
                cls.aggregate = args.aggregate
                if cls.aggregate and cls.max_events is None:
                        raise ValueError("-M/--max-events should be specified"
                                         " with -A/--aggregate")

        def __init__(self, probe, string_size, kernel_stack, user_stack,
                     cgroup_map_name, name, msg_filter):
                self.usdt = None
                self.streq_functions = ""
                self.raw_probe = probe
                self.string_size = string_size
                self.kernel_stack = kernel_stack
                self.user_stack = user_stack
                self.probe_user_list = set()
                Probe.probe_count += 1
                self._parse_probe()
                self.probe_num = Probe.probe_count
                self.probe_name = "probe_%s_%d" % \
                                (self._display_function(), self.probe_num)
                self.probe_name = re.sub(r'[^A-Za-z0-9_]', '_',
                                         self.probe_name)
                self.cgroup_map_name = cgroup_map_name
                if name is None:
                    # An empty bytestring is always contained in the command
                    # name so this will always succeed.
                    self.name = b''
                else:
                    self.name = name.encode('ascii')
                self.msg_filter = msg_filter
                # compiler can generate proper codes for function
                # signatures with "syscall__" prefix
                if self.is_syscall_kprobe:
                        self.probe_name = "syscall__" + self.probe_name[6:]

        def __str__(self):
                return "%s:%s:%s FLT=%s ACT=%s/%s" % (self.probe_type,
                        self.library, self._display_function(), self.filter,
                        self.types, self.values)

        def is_default_action(self):
                return self.python_format == ""

        def _bail(self, error):
                raise ValueError("error in probe '%s': %s" %
                                 (self.raw_probe, error))

        def _parse_probe(self):
                text = self.raw_probe

                # There might be a function signature preceding the actual
                # filter/print part, or not. Find the probe specifier first --
                # it ends with either a space or an open paren ( for the
                # function signature part.
                #                                          opt. signature
                #                               probespec       |      rest
                #                               ---------  ----------   --
                (spec, sig, rest) = re.match(r'([^ \t]+)(\([^\(]*\))?(.*)',
                                             text).groups()

                self._parse_spec(spec)
                # Remove the parens
                self.signature = sig[1:-1] if sig else None
                if self.signature and self.probe_type in ['u', 't']:
                        self._bail("USDT and tracepoint probes can't have " +
                                   "a function signature; use arg1, arg2, " +
                                   "... instead")

                text = rest.lstrip()
                # If we now have a (, wait for the balanced closing ) and that
                # will be the predicate
                self.filter = None
                if len(text) > 0 and text[0] == "(":
                        balance = 1
                        for i in range(1, len(text)):
                                if text[i] == "(":
                                        balance += 1
                                if text[i] == ")":
                                        balance -= 1
                                if balance == 0:
                                        self._parse_filter(text[:i + 1])
                                        text = text[i + 1:]
                                        break
                        if self.filter is None:
                                self._bail("unmatched end of predicate")

                if self.filter is None:
                        self.filter = "1"

                # The remainder of the text is the printf action
                self._parse_action(text.lstrip())

        def _parse_offset(self, func_and_offset):
                func, offset_str = func_and_offset.split("+")
                try:
                        if "x" in offset_str or "X" in offset_str:
                                offset = int(offset_str, 16)
                        else:
                                offset = int(offset_str)
                except ValueError:
                        self._bail("invalid offset format " +
                                   " '%s', must be decimal or hexadecimal" % offset_str)

                return func, offset

        def _parse_spec(self, spec):
                parts = spec.split(":")
                # Two special cases: 'func' means 'p::func', 'lib:func' means
                # 'p:lib:func'. Other combinations need to provide an empty
                # value between delimiters, e.g. 'r::func' for a kretprobe on
                # the function func.
                if len(parts) == 1:
                        parts = ["p", "", parts[0]]
                elif len(parts) == 2:
                        parts = ["p", parts[0], parts[1]]
                if len(parts[0]) == 0:
                        self.probe_type = "p"
                elif parts[0] in ["p", "r", "t", "u"]:
                        self.probe_type = parts[0]
                else:
                        self._bail("probe type must be '', 'p', 't', 'r', " +
                                   "or 'u', but got '%s'" % parts[0])
                self.offset = 0
                if "+" in parts[-1]:
                        parts[-1], self.offset = self._parse_offset(parts[-1])

                if self.probe_type == "t":
                        self.tp_category = parts[1]
                        self.tp_event = parts[2]
                        self.library = ""       # kernel
                        self.function = ""      # from TRACEPOINT_PROBE
                elif self.probe_type == "u":
                        # u:<library>[:<provider>]:<probe> where :<provider> is optional
                        self.library = parts[1]
                        self.usdt_name = ":".join(parts[2:])
                        self.function = ""      # no function, just address
                        # We will discover the USDT provider by matching on
                        # the USDT name in the specified library
                        self._find_usdt_probe()
                else:
                        self.library = ':'.join(parts[1:-1])
                        self.function = parts[-1]

                # only x64 syscalls needs checking, no other syscall wrapper yet.
                self.is_syscall_kprobe = False
                if self.probe_type == "p" and len(self.library) == 0 and \
                   self.function[:10] == "__x64_sys_":
                        self.is_syscall_kprobe = True

        def _find_usdt_probe(self):
                target = Probe.pid if Probe.pid and Probe.pid != -1 \
                                   else Probe.tgid
                self.usdt = USDT(path=self.library, pid=target)

                parts = self.usdt_name.split(":")
                if len(parts) == 1:
                        provider_name = None
                        usdt_name = parts[0].encode("ascii")
                else:
                        provider_name = parts[0].encode("ascii")
                        usdt_name = parts[1].encode("ascii")
                for probe in self.usdt.enumerate_probes():
                        if ((not provider_name or probe.provider == provider_name)
                                        and probe.name == usdt_name):
                                return  # Found it, will enable later
                self._bail("unrecognized USDT probe %s" % self.usdt_name)

        def _parse_filter(self, filt):
                self.filter = self._rewrite_expr(filt)

        def _parse_types(self, fmt):
                for match in re.finditer(
                            r'[^%]%(s|u|d|lu|llu|ld|lld|hu|hd|x|lx|llx|c|K|U)', fmt):
                        self.types.append(match.group(1))
                fmt = re.sub(r'([^%]%)(u|d|lu|llu|ld|lld|hu|hd)', r'\1d', fmt)
                fmt = re.sub(r'([^%]%)(x|lx|llx)', r'\1x', fmt)
                fmt = re.sub('%K|%U', '%s', fmt)
                self.python_format = fmt.strip('"')

        def _parse_action(self, action):
                self.values = []
                self.types = []
                self.python_format = ""
                if len(action) == 0:
                        return

                action = action.strip()
                match = re.search(r'(\".*?\"),?(.*)', action)
                if match is None:
                        self._bail("expected format string in \"s")

                self.raw_format = match.group(1)
                self._parse_types(self.raw_format)
                for part in re.split('(?<!"),', match.group(2)):
                        part = self._rewrite_expr(part)
                        if len(part) > 0:
                                self.values.append(part)

        aliases_arg = {
                "arg1": "PT_REGS_PARM1(ctx)",
                "arg2": "PT_REGS_PARM2(ctx)",
                "arg3": "PT_REGS_PARM3(ctx)",
                "arg4": "PT_REGS_PARM4(ctx)",
                "arg5": "PT_REGS_PARM5(ctx)",
                "arg6": "PT_REGS_PARM6(ctx)",
        }

        aliases_indarg = {
                "arg1": "({u64 _val; struct pt_regs *_ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);"
                        "  bpf_probe_read_kernel(&_val, sizeof(_val), &(PT_REGS_PARM1(_ctx))); _val;})",
                "arg2": "({u64 _val; struct pt_regs *_ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);"
                        "  bpf_probe_read_kernel(&_val, sizeof(_val), &(PT_REGS_PARM2(_ctx))); _val;})",
                "arg3": "({u64 _val; struct pt_regs *_ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);"
                        "  bpf_probe_read_kernel(&_val, sizeof(_val), &(PT_REGS_PARM3(_ctx))); _val;})",
                "arg4": "({u64 _val; struct pt_regs *_ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);"
                        "  bpf_probe_read_kernel(&_val, sizeof(_val), &(PT_REGS_PARM4(_ctx))); _val;})",
                "arg5": "({u64 _val; struct pt_regs *_ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);"
                        "  bpf_probe_read_kernel(&_val, sizeof(_val), &(PT_REGS_PARM5(_ctx))); _val;})",
                "arg6": "({u64 _val; struct pt_regs *_ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);"
                        "  bpf_probe_read_kernel(&_val, sizeof(_val), &(PT_REGS_PARM6(_ctx))); _val;})",
        }

        aliases_common = {
                "retval": "PT_REGS_RC(ctx)",
                "$uid": "(unsigned)(bpf_get_current_uid_gid() & 0xffffffff)",
                "$gid": "(unsigned)(bpf_get_current_uid_gid() >> 32)",
                "$pid": "(unsigned)(bpf_get_current_pid_tgid() & 0xffffffff)",
                "$tgid": "(unsigned)(bpf_get_current_pid_tgid() >> 32)",
                "$cpu": "bpf_get_smp_processor_id()",
                "$task": "((struct task_struct *)bpf_get_current_task())"
        }

        def _rewrite_expr(self, expr):
                # Find the occurances of any arg[1-6]@user. Use it later to
                # identify bpf_probe_read_user
                for matches in re.finditer(r'(arg[1-6])(@user)', expr):
                    if matches.group(1).strip() not in self.probe_user_list:
                        self.probe_user_list.add(matches.group(1).strip())
                # Remove @user occurrences from arg before resolving to its
                # corresponding aliases.
                expr = re.sub(r'(arg[1-6])@user', r'\1', expr)
                rdict = StrcmpRewrite.rewrite_expr(expr,
                            self.bin_cmp, self.library,
                            self.probe_user_list, self.streq_functions,
                            Probe.streq_index)
                expr = rdict["expr"]
                self.streq_functions = rdict["streq_functions"]
                Probe.streq_index = rdict["probeid"]
                alias_to_check = Probe.aliases_indarg \
                                    if self.is_syscall_kprobe \
                                    else Probe.aliases_arg
                # For USDT probes, we replace argN values with the
                # actual arguments for that probe obtained using
                # bpf_readarg_N macros emitted at BPF construction.
                if not self.probe_type == "u":
                    for alias, replacement in alias_to_check.items():
                        expr = expr.replace(alias, replacement)
                for alias, replacement in Probe.aliases_common.items():
                    expr = expr.replace(alias, replacement)
                return expr

        c_type = {"u": "unsigned int", "d": "int",
                  "lu": "unsigned long", "ld": "long",
                  "llu": "unsigned long long", "lld": "long long",
                  "hu": "unsigned short", "hd": "short",
                  "x": "unsigned int", "lx": "unsigned long",
                  "llx": "unsigned long long",
                  "c": "char", "K": "unsigned long long",
                  "U": "unsigned long long"}
        fmt_types = c_type.keys()

        def _generate_field_decl(self, idx):
                field_type = self.types[idx]
                if field_type == "s":
                        return "char v%d[%d];\n" % (idx, self.string_size)
                if field_type in Probe.fmt_types:
                        return "%s v%d;\n" % (Probe.c_type[field_type], idx)
                self._bail("unrecognized format specifier %s" % field_type)

        def _generate_data_decl(self):
                # The BPF program will populate values into the struct
                # according to the format string, and the Python program will
                # construct the final display string.
                self.events_name = "%s_events" % self.probe_name
                self.struct_name = "%s_data_t" % self.probe_name
                self.stacks_name = "%s_stacks" % self.probe_name
                stack_type = "BPF_STACK_TRACE" if self.build_id_enabled is False \
                             else "BPF_STACK_TRACE_BUILDID"
                stack_table = "%s(%s, 1024);" % (stack_type, self.stacks_name) \
                              if (self.kernel_stack or self.user_stack) else ""
                data_fields = ""
                for i, field_type in enumerate(self.types):
                        data_fields += "        " + \
                                       self._generate_field_decl(i)
                time_str = "u64 timestamp_ns;" if self.time_field else ""
                cpu_str = "int cpu;" if self.print_cpu else ""
                kernel_stack_str = "       int kernel_stack_id;" \
                                   if self.kernel_stack else ""
                user_stack_str = "       int user_stack_id;" \
                                 if self.user_stack else ""

                text = """
struct %s
{
%s
%s
        u32 tgid;
        u32 pid;
        char comm[TASK_COMM_LEN];
%s
%s
%s
        u32 uid;
};

BPF_PERF_OUTPUT(%s);
%s
"""
                return text % (self.struct_name, time_str, cpu_str, data_fields,
                               kernel_stack_str, user_stack_str,
                               self.events_name, stack_table)

        def _generate_field_assign(self, idx):
                field_type = self.types[idx]
                expr = self.values[idx].strip()
                text = ""
                if self.probe_type == "u" and expr[0:3] == "arg":
                        arg_index = int(expr[3])
                        arg_ctype = self.usdt.get_probe_arg_ctype(
                                self.usdt_name, arg_index - 1)
                        text = ("        %s %s = 0;\n" +
                                "        bpf_usdt_readarg(%s, ctx, &%s);\n") \
                                % (arg_ctype, expr, expr[3], expr)
                probe_read_func = "bpf_probe_read_kernel"
                if field_type == "s":
                        if self.library:
                            probe_read_func = "bpf_probe_read_user"
                        else:
                            alias_to_check = Probe.aliases_indarg \
                                                if self.is_syscall_kprobe \
                                                else Probe.aliases_arg
                            for arg, alias in alias_to_check.items():
                                if alias == expr and arg in self.probe_user_list:
                                    probe_read_func = "bpf_probe_read_user"
                                    break
                        return text + """
        if (%s != 0) {
                void *__tmp = (void *)%s;
                %s(&__data.v%d, sizeof(__data.v%d), __tmp);
        }
                """ % (expr, expr, probe_read_func, idx, idx)
                if field_type in Probe.fmt_types:
                        return text + "        __data.v%d = (%s)%s;\n" % \
                                        (idx, Probe.c_type[field_type], expr)
                self._bail("unrecognized field type %s" % field_type)

        def _generate_usdt_filter_read(self):
            text = ""
            if self.probe_type != "u":
                    return text
            for arg, _ in Probe.aliases_arg.items():
                    if not (arg in self.filter):
                            continue
                    arg_index = int(arg.replace("arg", ""))
                    arg_ctype = self.usdt.get_probe_arg_ctype(
                            self.usdt_name, arg_index - 1)
                    if not arg_ctype:
                            self._bail("Unable to determine type of {} "
                                       "in the filter".format(arg))
                    text += """
        {} {}_filter;
        bpf_usdt_readarg({}, ctx, &{}_filter);
                    """.format(arg_ctype, arg, arg_index, arg)
                    self.filter = self.filter.replace(
                            arg, "{}_filter".format(arg))
            return text

        def generate_program(self, include_self):
                data_decl = self._generate_data_decl()
                if Probe.pid != -1:
                        pid_filter = """
        if (__pid != %d) { return 0; }
                """ % Probe.pid
                # uprobes can have a built-in tgid filter passed to
                # attach_uprobe, hence the check here -- for kprobes, we
                # need to do the tgid test by hand:
                elif len(self.library) == 0 and Probe.tgid != -1:
                        pid_filter = """
        if (__tgid != %d) { return 0; }
                """ % Probe.tgid
                elif not include_self:
                        pid_filter = """
        if (__tgid == %d) { return 0; }
                """ % os.getpid()
                else:
                        pid_filter = ""

                if Probe.uid != -1:
                        uid_filter = """
        if (__uid != %d) { return 0; }
                """ % Probe.uid
                else:
                        uid_filter = ""

                if self.cgroup_map_name is not None:
                        cgroup_filter = """
        if (%s.check_current_task(0) <= 0) { return 0; }
                """ % self.cgroup_map_name
                else:
                        cgroup_filter = ""

                prefix = ""
                signature = "struct pt_regs *ctx"
                if self.signature:
                        signature += ", " + self.signature

                data_fields = ""
                for i, expr in enumerate(self.values):
                        data_fields += self._generate_field_assign(i)

                if self.probe_type == "t":
                        heading = "TRACEPOINT_PROBE(%s, %s)" % \
                                  (self.tp_category, self.tp_event)
                        ctx_name = "args"
                else:
                        heading = "int %s(%s)" % (self.probe_name, signature)
                        ctx_name = "ctx"

                time_str = """
        __data.timestamp_ns = bpf_ktime_get_ns();""" if self.time_field else ""
                cpu_str = """
        __data.cpu = bpf_get_smp_processor_id();""" if self.print_cpu else ""
                stack_trace = ""
                if self.user_stack:
                        stack_trace += """
        __data.user_stack_id = %s.get_stackid(
          %s, BPF_F_USER_STACK
        );""" % (self.stacks_name, ctx_name)
                if self.kernel_stack:
                        stack_trace += """
        __data.kernel_stack_id = %s.get_stackid(
          %s, 0
        );""" % (self.stacks_name, ctx_name)

                text = heading + """
{
        u64 __pid_tgid = bpf_get_current_pid_tgid();
        u32 __tgid = __pid_tgid >> 32;
        u32 __pid = __pid_tgid; // implicit cast to u32 for bottom half
        u32 __uid = bpf_get_current_uid_gid();
        %s
        %s
        %s
        %s
        %s
        if (!(%s)) return 0;

        struct %s __data = {0};
        %s
        %s
        __data.tgid = __tgid;
        __data.pid = __pid;
        __data.uid = __uid;
        bpf_get_current_comm(&__data.comm, sizeof(__data.comm));
%s
%s
        %s.perf_submit(%s, &__data, sizeof(__data));
        return 0;
}
"""
                text = text % (pid_filter, uid_filter, cgroup_filter, prefix,
                               self._generate_usdt_filter_read(), self.filter,
                               self.struct_name, time_str, cpu_str, data_fields,
                               stack_trace, self.events_name, ctx_name)

                return self.streq_functions + data_decl + "\n" + text

        @classmethod
        def _time_off_str(cls, timestamp_ns):
            offset = 1e-9 * (timestamp_ns - cls.first_ts)
            if cls.print_unix_timestamp:
                return "%.6f" % (offset + cls.first_ts_real)
            else:
                return "%.6f" % offset

        def _display_function(self):
                if self.probe_type == 'p' or self.probe_type == 'r':
                        return self.function
                elif self.probe_type == 'u':
                        return self.usdt_name
                else:   # self.probe_type == 't'
                        return self.tp_event

        def _stack_to_string(self, bpf, stack_id, tgid):
            if stack_id < 0:
                return ("        %d" % stack_id)

            stackstr = ''
            stack = list(bpf.get_table(self.stacks_name).walk(stack_id))
            for addr in stack:
                stackstr += '        '
                if Probe.print_address:
                    stackstr += ("%16x " % addr)
                symstr = bpf.sym(addr, tgid, show_module=True, show_offset=True)
                stackstr += ('%s\n' % (symstr.decode('utf-8')))

            return stackstr

        def _format_message(self, bpf, tgid, values):
                # Replace each %K with kernel sym and %U with user sym in tgid
                kernel_placeholders = [i for i, t in enumerate(self.types)
                                       if t == 'K']
                user_placeholders = [i for i, t in enumerate(self.types)
                                     if t == 'U']
                string_placeholders = [i for i, t in enumerate(self.types)
                                       if t == 's']
                for kp in kernel_placeholders:
                    values[kp] = bpf.ksym(values[kp], show_offset=True)
                for up in user_placeholders:
                    values[up] = bpf.sym(values[up], tgid,
                                         show_module=True, show_offset=True)
                for sp in string_placeholders:
                    values[sp] = values[sp].decode('utf-8', 'replace')
                return self.python_format % tuple(values)

        def print_aggregate_events(self):
                for k, v in sorted(self.symcount.items(), key=lambda item: \
                                   item[1], reverse=True):
                    print("%s-->COUNT %d\n\n" % (k, v), end="")

        def print_event(self, bpf, cpu, data, size):
                event = bpf[self.events_name].event(data)
                if self.name not in event.comm:
                    return
                values = list(map(lambda i: getattr(event, "v%d" % i),
                             range(0, len(self.values))))
                msg = self._format_message(bpf, event.tgid, values)
                if self.msg_filter and self.msg_filter not in msg:
                    return
                eventstr = ''
                if Probe.print_time:
                    time = strftime("%H:%M:%S") if Probe.use_localtime else \
                           Probe._time_off_str(event.timestamp_ns)
                    if Probe.print_unix_timestamp:
                        eventstr += ("%-17s " % time[:17])
                    else:
                        eventstr += ("%-8s " % time[:8])
                if Probe.print_cpu:
                    eventstr += ("%-3s " % event.cpu)
                eventstr += ("%-7d %-7d %-15s %-16s %s\n" %
                      (event.tgid, event.pid,
                       event.comm.decode('utf-8', 'replace'),
                       self._display_function(), msg))

                if self.kernel_stack:
                        eventstr += self._stack_to_string(bpf, event.kernel_stack_id, -1)
                if self.user_stack:
                        eventstr += self._stack_to_string(bpf, event.user_stack_id, event.tgid)

                if self.aggregate is False:
                    print(eventstr, end="")
                    if self.kernel_stack or self.user_stack:
                        print("")
                else:
                    if eventstr in self.symcount:
                        self.symcount[eventstr] += 1
                    else:
                        self.symcount[eventstr] = 1

                Probe.event_count += 1
                if Probe.max_events is not None and \
                   Probe.event_count >= Probe.max_events:
                    if self.aggregate:
                        self.print_aggregate_events()
                    sys.stdout.flush()
                    Probe.done = True;

        def attach(self, bpf, verbose):
                if len(self.library) == 0:
                        self._attach_k(bpf)
                else:
                        self._attach_u(bpf)
                callback = partial(self.print_event, bpf)
                bpf[self.events_name].open_perf_buffer(callback,
                        page_cnt=self.page_cnt)

        def _attach_k(self, bpf):
                if self.probe_type == "r":
                        bpf.attach_kretprobe(event=self.function,
                                             fn_name=self.probe_name)
                elif self.probe_type == "p":
                        bpf.attach_kprobe(event=self.function,
                                          fn_name=self.probe_name,
                                          event_off=self.offset)
                # Note that tracepoints don't need an explicit attach

        def _attach_u(self, bpf):
                libpath = BPF.find_library(self.library)
                if libpath is None:
                        # This might be an executable (e.g. 'bash')
                        libpath = BPF.find_exe(self.library)
                if libpath is None or len(libpath) == 0:
                        self._bail("unable to find library %s" % self.library)

                if self.probe_type == "u":
                        pass    # Was already enabled by the BPF constructor
                elif self.probe_type == "r":
                        bpf.attach_uretprobe(name=libpath,
                                             sym=self.function,
                                             fn_name=self.probe_name,
                                             pid=Probe.tgid)
                else:
                        bpf.attach_uprobe(name=libpath,
                                          sym=self.function,
                                          fn_name=self.probe_name,
                                          pid=Probe.tgid,
                                          sym_off=self.offset)

class Tool(object):
        DEFAULT_PERF_BUFFER_PAGES = 64
        examples = """
EXAMPLES:

trace do_sys_open
        Trace the open syscall and print a default trace message when entered
trace kfree_skb+0x12
        Trace the kfree_skb kernel function after the instruction on the 0x12 offset
trace 'do_sys_open "%s", arg2@user'
        Trace the open syscall and print the filename being opened @user is
        added to arg2 in kprobes to ensure that char * should be copied from
        the userspace stack to the bpf stack. If not specified, previous
        behaviour is expected.

trace 'do_sys_open "%s", arg2@user' -n main
        Trace the open syscall and only print event that process names containing "main"
trace 'do_sys_open "%s", arg2@user' --uid 1001
        Trace the open syscall and only print event that processes with user ID 1001
trace 'do_sys_open "%s", arg2@user' -f config
        Trace the open syscall and print the filename being opened filtered by "config"
trace 'sys_read (arg3 > 20000) "read %d bytes", arg3'
        Trace the read syscall and print a message for reads >20000 bytes
trace 'r::do_sys_open "%llx", retval'
        Trace the return from the open syscall and print the return value
trace 'c:open (arg2 == 42) "%s %d", arg1, arg2'
        Trace the open() call from libc only if the flags (arg2) argument is 42
trace 'c:malloc "size = %d", arg1'
        Trace malloc calls and print the size being allocated
trace 'p:c:write (arg1 == 1) "writing %d bytes to STDOUT", arg3'
        Trace the write() call from libc to monitor writes to STDOUT
trace 'r::__kmalloc (retval == 0) "kmalloc failed!"'
        Trace returns from __kmalloc which returned a null pointer
trace 'r:c:malloc (retval) "allocated = %x", retval'
        Trace returns from malloc and print non-NULL allocated buffers
trace 't:block:block_rq_complete "sectors=%d", args->nr_sector'
        Trace the block_rq_complete kernel tracepoint and print # of tx sectors
trace 'u:pthread:pthread_create (arg4 != 0)'
        Trace the USDT probe pthread_create when its 4th argument is non-zero
trace 'u:pthread:libpthread:pthread_create (arg4 != 0)'
        Ditto, but the provider name "libpthread" is specified.
trace 'p::SyS_nanosleep(struct timespec *ts) "sleep for %lld ns", ts->tv_nsec'
        Trace the nanosleep syscall and print the sleep duration in ns
trace -c /sys/fs/cgroup/system.slice/workload.service '__x64_sys_nanosleep' '__x64_sys_clone'
        Trace nanosleep/clone syscall calls only under workload.service
        cgroup hierarchy.
trace -I 'linux/fs.h' \\
      'p::uprobe_register(struct inode *inode) "a_ops = %llx", inode->i_mapping->a_ops'
        Trace the uprobe_register inode mapping ops, and the symbol can be found
        in /proc/kallsyms
trace -I 'kernel/sched/sched.h' \\
      'p::__account_cfs_rq_runtime(struct cfs_rq *cfs_rq) "%d", cfs_rq->runtime_remaining'
        Trace the cfs scheduling runqueue remaining runtime. The struct cfs_rq is defined
        in kernel/sched/sched.h which is in kernel source tree and not in kernel-devel
        package.  So this command needs to run at the kernel source tree root directory
        so that the added header file can be found by the compiler.
trace -I 'net/sock.h' \\
      'udpv6_sendmsg(struct sock *sk) (sk->sk_dport == 13568)'
        Trace udpv6 sendmsg calls only if socket's destination port is equal
        to 53 (DNS; 13568 in big endian order)
trace -I 'linux/fs_struct.h' 'mntns_install "users = %d", $task->fs->users'
        Trace the number of users accessing the file system of the current task
trace -s /lib/x86_64-linux-gnu/libc.so.6,/bin/ping 'p:c:inet_pton' -U
        Trace inet_pton system call and use the specified libraries/executables for
        symbol resolution.
"""

        def __init__(self):
                parser = argparse.ArgumentParser(description="Attach to " +
                  "functions and print trace messages.",
                  formatter_class=argparse.RawDescriptionHelpFormatter,
                  epilog=Tool.examples)
                parser.add_argument("-b", "--buffer-pages", type=int,
                  default=Tool.DEFAULT_PERF_BUFFER_PAGES,
                  help="number of pages to use for perf_events ring buffer "
                       "(default: %(default)d)")
                # we'll refer to the userspace concepts of "pid" and "tid" by
                # their kernel names -- tgid and pid -- inside the script
                parser.add_argument("-p", "--pid", type=int, metavar="PID",
                  dest="tgid", help="id of the process to trace (optional)")
                parser.add_argument("-L", "--tid", type=int, metavar="TID",
                  dest="pid", help="id of the thread to trace (optional)")
                parser.add_argument("--uid", type=int, metavar="UID",
                  dest="uid", help="id of the user to trace (optional)")
                parser.add_argument("-v", "--verbose", action="store_true",
                  help="print resulting BPF program code before executing")
                parser.add_argument("-Z", "--string-size", type=int,
                  default=80, help="maximum size to read from strings")
                parser.add_argument("-S", "--include-self",
                  action="store_true",
                  help="do not filter trace's own pid from the trace")
                parser.add_argument("-M", "--max-events", type=int,
                  help="number of events to print before quitting")
                parser.add_argument("-t", "--timestamp", action="store_true",
                  help="print timestamp column (offset from trace start)")
                parser.add_argument("-u", "--unix-timestamp", action="store_true",
                  help="print UNIX timestamp instead of offset from trace start, requires -t")
                parser.add_argument("-T", "--time", action="store_true",
                  help="print time column")
                parser.add_argument("-C", "--print_cpu", action="store_true",
                  help="print CPU id")
                parser.add_argument("-c", "--cgroup-path", type=str,
                  metavar="CGROUP_PATH", dest="cgroup_path",
                  help="cgroup path")
                parser.add_argument("-n", "--name", type=str,
                                    help="only print process names containing this name")
                parser.add_argument("-f", "--msg-filter", type=str, dest="msg_filter",
                                    help="only print the msg of event containing this string")
                parser.add_argument("-B", "--bin_cmp", action="store_true",
                  help="allow to use STRCMP with binary values")
                parser.add_argument('-s', "--sym_file_list", type=str,
                  metavar="SYM_FILE_LIST", dest="sym_file_list",
                  help="comma separated list of symbol files to use \
                  for symbol resolution")
                parser.add_argument("-K", "--kernel-stack",
                  action="store_true", help="output kernel stack trace")
                parser.add_argument("-U", "--user-stack",
                  action="store_true", help="output user stack trace")
                parser.add_argument("-a", "--address", action="store_true",
                  help="print virtual address in stacks")
                parser.add_argument(metavar="probe", dest="probes", nargs="+",
                  help="probe specifier (see examples)")
                parser.add_argument("-I", "--include", action="append",
                  metavar="header",
                  help="additional header files to include in the BPF program "
                       "as either full path, "
                       "or relative to current working directory, "
                       "or relative to default kernel header search path")
                parser.add_argument("-A", "--aggregate", action="store_true",
                  help="aggregate amount of each trace")
                parser.add_argument("--ebpf", action="store_true",
                  help=argparse.SUPPRESS)
                self.args = parser.parse_args()
                if self.args.tgid and self.args.pid:
                        parser.error("only one of -p and -L may be specified")
                if self.args.cgroup_path is not None:
                        self.cgroup_map_name = "__cgroup"
                else:
                        self.cgroup_map_name = None

        def _create_probes(self):
                Probe.configure(self.args)
                self.probes = []
                for probe_spec in self.args.probes:
                        self.probes.append(Probe(
                                probe_spec, self.args.string_size,
                                self.args.kernel_stack, self.args.user_stack,
                                self.cgroup_map_name, self.args.name, self.args.msg_filter))

        def _generate_program(self):
                self.program = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

"""
                for include in (self.args.include or []):
                        if include.startswith((".", "/")):
                                include = os.path.abspath(include)
                                self.program += "#include \"%s\"\n" % include
                        else:
                                self.program += "#include <%s>\n" % include
                self.program += BPF.generate_auto_includes(
                        map(lambda p: p.raw_probe, self.probes))
                if self.cgroup_map_name is not None:
                        self.program += "BPF_CGROUP_ARRAY(%s, 1);\n" % \
                                        self.cgroup_map_name
                for probe in self.probes:
                        self.program += probe.generate_program(
                                        self.args.include_self)

                if self.args.verbose or self.args.ebpf:
                        print(self.program)
                        if self.args.ebpf:
                                exit()

        def _attach_probes(self):
                usdt_contexts = []
                for probe in self.probes:
                    if probe.usdt:
                        # USDT probes must be enabled before the BPF object
                        # is initialized, because that's where the actual
                        # uprobe is being attached.
                        probe.usdt.enable_probe(
                                probe.usdt_name, probe.probe_name)
                        if self.args.verbose:
                                print(probe.usdt.get_text())
                        usdt_contexts.append(probe.usdt)
                self.bpf = BPF(text=self.program, usdt_contexts=usdt_contexts)
                if self.args.sym_file_list is not None:
                  print("Note: Kernel bpf will report stack map with ip/build_id")
                  map(lambda x: self.bpf.add_module(x), self.args.sym_file_list.split(','))

                # if cgroup filter is requested, update the cgroup array map
                if self.cgroup_map_name is not None:
                        cgroup_array = self.bpf.get_table(self.cgroup_map_name)
                        cgroup_array[0] = self.args.cgroup_path

                for probe in self.probes:
                        if self.args.verbose:
                                print(probe)
                        probe.attach(self.bpf, self.args.verbose)

        def _main_loop(self):
                all_probes_trivial = all(map(Probe.is_default_action,
                                             self.probes))

                # Print header
                if self.args.timestamp or self.args.time:
                    col_fmt = "%-17s " if self.args.unix_timestamp else "%-8s "
                    print(col_fmt % "TIME", end="")
                if self.args.print_cpu:
                    print("%-3s " % "CPU", end="")
                print("%-7s %-7s %-15s %-16s %s" %
                      ("PID", "TID", "COMM", "FUNC",
                      "-" if not all_probes_trivial else ""))
                sys.stdout.flush()

                while not Probe.done:
                        self.bpf.perf_buffer_poll()

        def run(self):
                try:
                        self._create_probes()
                        self._generate_program()
                        self._attach_probes()
                        self._main_loop()
                except:
                        exc_info = sys.exc_info()
                        sys_exit = exc_info[0] is SystemExit
                        if self.args.verbose:
                                traceback.print_exc()
                        elif not sys_exit:
                                print(exc_info[1])
                        exit(0 if sys_exit else 1)

if __name__ == "__main__":
        Tool().run()
