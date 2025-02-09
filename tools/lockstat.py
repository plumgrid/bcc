#!/usr/bin/env python3
# Copyright 2018 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# lockstat - Display lock contention stats from locktrace file
#
# 28-Jul-2017   Gisle Dankel   Created this.
#

from __future__ import division
from __future__ import unicode_literals
from __future__ import absolute_import
from __future__ import print_function
from collections import defaultdict
from collections import namedtuple
from pathlib import Path
import argparse
import ast
import itertools
import os
import signal
import subprocess
import textwrap

script = os.path.basename(__file__)

examples = """
EXAMPLES:
{0}
        Profile all processes until ctrl-c and print reports of significant ones
{0} 10
        Profile all processes for 10 seconds
{0} -p 12345
        Profile only pid 12345 for 5 seconds
{0} -C blocked.sum,tid.count,lock -p 12345
        Show these columns only.
{0} -g comm -s blocked.max -p 12345
        Group by thread name and sort by max block time
{0} -g stack -c -p 12345
        Group by callstack and show full stacks
{0} -i locks.txt
        Instead of tracing, read a pre-generated trace file
""".format(script)


description = """
Display aggregate lock stats in a tabular format
"""

column_help = """
Available columns:
blocked.(sum|count|max|avg) - Time / count blocked (sleeping) on a lock
sys.(sum|count|max|avg) - Time / count executing in sys_futex
lock(.count) - Top lock address / number of locks
tid(.count) - Top tid / number of tids
comm(.count) - Thread name
"""


# arg validation
def column_name(val):
    colnames = {
        'blocked.sum': 'blocked_us',
        'blocked.count': 'blocked_count',
        'blocked.max': 'max_blocked_us',
        'blocked.avg': 'avg_blocked_us',
        'sys.sum': 'sys_futex_us',
        'sys.count': 'sys_futex_count',
        'sys.max': 'max_sys_futex_us',
        'sys.avg': 'avg_sys_futex_us',
        'wait.count': 'wait_count',
        'wake.count': 'wake_count',
        'lock': 'addr',
        'lock.count': 'addr_count',
        'comm': 'comm',
        'comm.count': 'comm_count',
        'tid': 'tid',
        'tid.count': 'tid_count',
        'stack': 'usr_syms',
        'stack.count': 'usr_syms_count',
    }
    try:
        return colnames[val]
    except KeyError as e:
        raise argparse.ArgumentTypeError("Unknown column name: " + e.args[0])


def column_name_list(val):
    val = val.replace('blocked.*',
                      'blocked.sum,blocked.count,blocked.avg,blocked.max')
    val = val.replace('sys.*', 'sys.sum,sys.count,sys.avg,sys.max')
    return [column_name(name) for name in val.split(',')]


default_columns =\
    "blocked.count,blocked.sum,sys.sum,lock,lock.count,tid.count,stack.count"

stat_dims = ['addr', 'usr_syms', 'tid', 'comm']


def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

def event_type(val):
    valid = ['lock', 'cond', 'all']
    if val not in valid:
        raise argparse.ArgumentTypeError("Must be one of " + ",".join(valid))
    return val

def group_type(val):
    dim = column_name(val)
    if dim not in stat_dims:
        raise argparse.ArgumentTypeError("Must be one of " + ",".join(stat_dims))
    return dim

parser = argparse.ArgumentParser(
    description=description,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=(column_help + examples))
parser.add_argument("-p", "--pid", type=positive_int,
                    help="Show stats for this pid only")
parser.add_argument("-e", "--event", type=event_type, default='lock',
                    help="Show locks (lock), conditional waits (cond) " +
                         "or both (all)")
parser.add_argument("-s", "--sort-by", type=column_name, default='blocked.sum',
                    help="Sort by this column")
parser.add_argument("-g", "--group-by", type=group_type, default='lock',
                    help="Group by lock, stack, comm or tid")
parser.add_argument("-C", "--columns", type=column_name_list,
                    default=default_columns,
                    help="Include these columns. " +
                         "See list of column names below. Default=" +
                         default_columns)
parser.add_argument("-c", "--callstack", action="store_true",
                    help="Display full callstacks")
parser.add_argument("-i", "--input-file", type=Path,
                    help="Don't trace - read the specified trace file instead.")
parser.add_argument("-d", "--debug", action="store_true",
                    help="Display extra stats used for sanity checking / " +
                         "debugging. Ignored when -i is used.")
parser.add_argument("--hist", type=str,
                    help="Write per-lock histograms to the specified file." +
                         "Ignored when -i is used")
parser.add_argument("--stack-storage-size", default=1024,
                    type=positive_nonzero_int,
                    help="the number of unique stack traces that can be stored "
                         "and displayed. Ignored when -i is used")
parser.add_argument("duration", nargs="?", default=99999999,
                    type=positive_nonzero_int,
                    help="Duration of trace, in seconds. Ignored when -i is used.")

args = parser.parse_args()


# TODO: A bunch of this code can be replaced with pandas dataframes
# For now I have avoided this dependency for easier deployment
# but this might change in the future
class Table(object):
    def __init__(self, cols, data, agg=None):
        self.__cols = {col: idx for idx, col in enumerate(cols)}
        self.__rows = data
        self.__agg = {col: Table.__default_agg for col in cols}
        if agg:
            self.__agg.update(agg)

    def set_aggregators(self, agg):
        self.__agg.update(agg)

    def __getitem__(self, idx):
        if idx in self.__cols:
            return [row[self.__cols[idx]] for row in self.__rows]
        return dict(zip(self.__cols, self.__rows[idx]))

    def count(self):
        return len(self.__rows)

    def col_width(self, col):
        idx = self.__cols[col]
        return max(len(str(row[idx])) for row in self.__rows)

    @staticmethod
    def __default_agg(vals):
        if isinstance(vals[0], str):
            return list(set(vals))
        if isinstance(vals[0], list):
            return list({v1 for v in vals for v1 in v})
        return sum(vals)

    def __group_by(self, *cols):
        res = defaultdict(list)
        for row in self.__rows:
            key = tuple(row[self.__cols[col]] for col in cols)
            res[key].append(row)
        return res

    # Sum across one or more dimensions - reduces the number of dimensions
    def sum(self, *preserve, use_agg=None):
        agg = self.__agg.copy()
        if use_agg is not None:
            agg.update(use_agg)
        agg.update({p: lambda c: c[0] for p in preserve})
        res = [
            [agg[c]([row[idx] for row in rows])
                for c, idx in self.__cols.items()]
            for rows in self.__group_by(*preserve).values()
        ]
        return Table(self.__cols, res, agg=self.__agg.copy())

    def sum_all(self, use_agg=None):
        if self.count() == 0:
            return {col: 0 for col in self.__cols}
        return self.sum(use_agg=use_agg)[0]

    def sort(self, col, reverse=True):
        idx = self.__cols[col]
        res = sorted(self.__rows, key=lambda row: row[idx], reverse=reverse)
        return Table(self.__cols, res, agg=self.__agg.copy())

    # Returns a dictionary of Tables
    def group_by(self, *cols):
        return {
            key: Table(self.__cols, group, agg=self.__agg.copy())
            for key, group in self.__group_by(*cols).items()
        }

    # Filter rows by column
    def filter(self, col, f):
        res = [row for row in self.__rows if f(row[self.__cols[col]])]
        return Table(self.__cols, res, agg=self.__agg.copy())

    def __repr__(self):
        header = ",".join(self.__cols)
        rows = [",".join(map(str, row)) for row in self.__rows]
        return header + "\n" + "\n".join(rows) + "\n"


def stack_syms(stack):
    return stack.split(';')


def caller_string(syms):
    if len(syms) == 0 or syms[0] == '':
        return 'No stack'
    if len(syms) == 1:
        return shorten_symbol(syms[0])
    top = 1 + first_interesting_caller(syms[1:])
    arrow = " <-.. " if top > 2 else " <-- "
    return shorten_symbol(syms[1]) + arrow + shorten_symbol(syms[top])


def sym_base(sym):
    return sym.split('(')[0].split("::")[-1]


def first_interesting_caller(syms):
    for idx, sym in enumerate(syms[1:], start=1):
        base = sym_base(sym)
        if "mutex" in base or "lock" in base or "[unknown]" in sym:
            continue
        return idx
    return len(syms) - 1


def shorten_symbol(sym):
    if sym == '[unknown]' or sym == '':
            return "No symbol"
    res = ""
    open_brackets = 0
    for char in sym:
            if char in ")>":
                    open_brackets -= 1
            if open_brackets == 0:
                    res += char
            if char in "(<":
                    open_brackets += 1
    return res


def us_to_ms(x):
    return round(x / 1000.0)


def us_to_s(x):
    return round(x / 1000000.0)


def ms_to_s(x):
    return round(x / 1000.0)


def ms_to_us(x):
    return x * 1000


def is_cond_wait(syms):
    return "pthread_cond_" in syms or\
           "futexWait" in syms or "tryWaitSlow" in syms


def is_not_cond_wait(syms):
    return not is_cond_wait(syms)


def is_lock(sym):
    syml = sym_base(sym).lower()
    return ("_lock" in syml or "mutex" in syml or "::lock" in syml) and\
           "locked" not in syml


def is_atomic(syms):
    return "__add_atomic" in syms or "__exchange_and_add" in syms


def is_sys_trace(syms):
    return "syscall_trace_enter" in syms


def is_sys_futex(syms):
    return "futex_wait" in syms or "futex_wake" in syms


def lock_in_callstack(syms):
    if is_cond_wait(syms):
        return False
    for sym in syms.split(';'):
        if is_lock(sym):
            return True
    return False


def indent_block(text, ind):
    return "\n".join(map(lambda x: ind + x, text.split("\n")))


def pct(v, of):
    return round(100.0 * v / of)


def print_summary_for_pid(pid, stats, duration):
    tot_all = stats.sum_all()
    locks = stats.filter('usr_syms', is_not_cond_wait)
    tot_locks = locks.sum_all()
    tot_other = stats.filter('usr_syms', is_cond_wait).sum_all()
    usr_locks = stats.filter('usr_syms', lock_in_callstack).sum_all()
    usr_atomics = stats.filter('usr_syms', is_atomic).sum_all()
    sys_futex = stats.filter('kernel_syms', is_sys_futex)
    futex_locks = sys_futex.filter('usr_syms', is_not_cond_wait).sum_all()
    futex_cond = sys_futex.filter('usr_syms', is_cond_wait).sum_all()
    sys_trace = stats.filter('kernel_syms', is_sys_trace).sum_all()

    indent = "  "
    print("")
    total_sys_time_ms = tot_all['sys_ms']
    total_run_time_ms = total_sys_time_ms + tot_all['usr_ms']
    blocked_ms = us_to_ms(tot_locks['blocked_us'])
    total_run_and_block_time_ms = total_run_time_ms + blocked_ms
    sys_futex_ms = us_to_ms(tot_all['sys_futex_us'])
    sys_futex_count = tot_all['wait_count'] + tot_all['wake_count']
    sys_futex_locks = tot_locks['wait_count'] + tot_locks['wake_count']
    sys_futex_other = tot_other['wait_count'] + tot_other['wake_count']
    exec_locks_ms = sys_futex_ms + usr_locks['usr_ms']
    wait_ms = us_to_ms(tot_other['blocked_us'])

    summary = textwrap.dedent("""
        Observed threads:                  %i
        Observed locks:                    %i
        Observed comms:                    %i
        Sys_futex calls:                   %i (%i/%i/%i wait/blk/wake)
        Sys_futex_calls (locks):           %i (%i/%i/%i wait/blk/wake)
        Sys_futex_calls (other):           %i (%i/%i/%i wait/blk/wake)
          (cond waits / semaphores / etc)
        Runtime:                           %is (%is sys, %is wall clock)
        Blocked on locks:                  %is (%i%% of run+block)
        Executing locks:                   %ims (%i%% of run, %ims usr, %ims sys)
        Executing usr atomics:             %ims (%i%% of run)
        Waiting on cond var:               %is (%i%% of run+block+wait)
        Sampled vs. timestamps futex:      %ims vs %ims and %i vs %ims lock/cond
        Tracing overhead:                  %ims (%i%% of run)
    """ % (
        len(set(stats['tid'])),
        len(set(stats['addr'])),
        len(set(stats['comm'])),
        sys_futex_count, tot_all['wait_count'],
        tot_all['blocked_count'], tot_all['wake_count'],
        sys_futex_locks, tot_locks['wait_count'],
        tot_locks['blocked_count'], tot_locks['wake_count'],
        sys_futex_other, tot_other['wait_count'],
        tot_other['blocked_count'], tot_other['wake_count'],
        ms_to_s(total_run_time_ms), ms_to_s(total_sys_time_ms), duration,
        ms_to_s(blocked_ms), pct(blocked_ms, total_run_and_block_time_ms),
        exec_locks_ms, pct(exec_locks_ms, total_run_time_ms),
        usr_locks['usr_ms'], sys_futex_ms,
        usr_atomics['usr_ms'], pct(usr_atomics['usr_ms'], total_run_time_ms),
        ms_to_s(wait_ms), pct(wait_ms, total_run_time_ms + blocked_ms + wait_ms),
        futex_locks['sys_ms'], us_to_ms(tot_locks['sys_futex_us']),
        futex_cond['sys_ms'], us_to_ms(tot_other['sys_futex_us']),
        sys_trace['sys_ms'], pct(sys_trace['sys_ms'], total_run_time_ms),
        )
    )
    comm = stats.sort('usr_ms')[0]['comm']
    print(indent + "Summary for %s (%d):" % (comm, pid))
    print(indent + "-" * 40)
    print(indent_block(summary, indent))


Formatter = namedtuple('Formatter', ['header', 'sub_header', 'width', 'fmt'])

def ms_fmt(val_us):
    return str(us_to_ms(val_us))

def stack_fmt(callstack):
    return "None" if len(stack_syms(callstack)) == 0 \
            else caller_string(stack_syms(callstack))

formatters = {
    'addr': Formatter('Lock Address', '', 18, lambda v: "0x%x" % (v)),
    'blocked_us': Formatter('Blocked', 'Sum ms', 7, ms_fmt),
    'sys_futex_us': Formatter('SysFutx', 'Sum ms', 7, ms_fmt),
    'max_blocked_us': Formatter('Blocked', 'Max us', 10, str),
    'max_sys_futex_us': Formatter('SysFutx', 'Max us', 10, str),
    'avg_blocked_us': Formatter('Blocked', 'Avg us', 7, str),
    'avg_sys_futex_us': Formatter('SysFutx', 'Avg us', 7, str),
    'blocked_count': Formatter('Blocked', '#', 7, str),
    'wait_count': Formatter('Wait', '#', 7, str),
    'wake_count': Formatter('Wake', '#', 7, str),
    'sys_futex_count': Formatter('SysFutx', '#', 7, str),
    'errors': Formatter('Errors', '#', 7, str),
    'tid': Formatter('TID', '', 6, str),
    'tid_count': Formatter('TIDs', '#', 4, str),
    'comm': Formatter('Thread Name', '', 16, str),
    'comm_count': Formatter('Comm', '#', 4, str),
    'pct_this': Formatter('This', '%', 4, str),
    'pct_cuml': Formatter('Cuml', '%', 4, str),
    'addr_count': Formatter('Locks', '#', 7, str),
    'usr_syms': Formatter('Caller', '', 40, stack_fmt),
    'usr_syms_count': Formatter('Callers', '#', 7, str),
}


def aggregate_unique(tids):
    if isinstance(tids[0], list):
        return list(set(itertools.chain(*tids)))
    return list(set(tids))


def divide_or_zero(a, b):
    return 0 if b == 0 else round(a / b)


def add_derived_stats(total, sorted_stats, group_by, order_by):
    total['avg_blocked_us'] =\
        divide_or_zero(total['blocked_us'], total['blocked_count'])
    total['sys_futex_count'] = total['wait_count'] + total['wake_count']
    total['avg_sys_futex_us'] =\
        divide_or_zero(total['sys_futex_us'], total['sys_futex_count'])
    for dim in stat_dims:
        total[dim + "_count"] = len(total[dim])
        total[dim] = sorted_stats.sum(dim).sort(order_by)[dim][0]

def print_stats_for_pid(pid, stats, full_stacks, syms,
                        order_by, group_by, columns):
    indent = "  "
    if order_by in columns:
        columns.remove(order_by)
    if group_by in columns:
        columns.remove(group_by)
    if group_by + "_count" in columns:
        columns.remove(group_by + "_count")
    if 'max' not in order_by:
        columns = [order_by, 'pct_this', 'pct_cuml'] + columns
    else:
        columns.insert(0, order_by)
    if group_by != syms:
        columns.append(group_by)
    columns.append(syms)

    # Header
    widths = [
        max(formatters[col].width, len(formatters[col].header),
            len(formatters[col].sub_header))
        for col in columns]
    padded = zip(widths, [formatters[col].header for col in columns])
    header = ("%-*s " * len(columns)) % tuple(x for p in padded for x in p)
    padded = zip(widths, [formatters[col].sub_header for col in columns])
    sub_header = ("%*s " * len(columns)) % tuple(x for p in padded for x in p)
    print(indent + header)
    print(indent + sub_header)
    print(indent + ('-' * len(header)))

    # Aggregate, group and print table
    stats.set_aggregators({dim: aggregate_unique for dim in stat_dims})
    stats.set_aggregators({
        'max_blocked_us': max, 'max_sys_futex_us': max})
    agg_stats = stats.group_by(group_by)
    total = stats.sum_all()
    total_so_far = 0
    for sub_stats in sorted(
            agg_stats.values(),
            key=lambda x: x.sum_all()[order_by], reverse=True):
        sub_stats = sub_stats.sort(order_by)
        subtotal = sub_stats.sum_all()
        add_derived_stats(subtotal, sub_stats, group_by, order_by)
        order_by_val = subtotal[order_by]
        total_so_far += order_by_val
        subtotal['pct_this'] = round(100.0 * order_by_val / total[order_by])
        subtotal['pct_cuml'] = round(100.0 * total_so_far / total[order_by])
        str_values = [formatters[col].fmt(subtotal[col]) for col in columns]
        padded = zip(widths, str_values)
        row = ("%*s " * (len(columns) - 1) + "%-*s") %\
              tuple(x for p in padded for x in p)
        print(indent + row)
        if full_stacks:
            stack_indent = " " * (len(header) - formatters[syms].width)
            for sym in stack_syms(subtotal[syms]):
                print(indent + stack_indent + shorten_symbol(sym))
        # Don't print long tails
        # TODO: Add flag to print everything?
        if subtotal['pct_cuml'] == 100 or\
           formatters[order_by].fmt(order_by_val) == "0":
            break


def to_literal(s):
    if s == '':
        return s
    try:
        return ast.literal_eval(s)
    except ValueError:
        return s


def read_tracefile(filename, force_types):
    res = defaultdict(list)
    with open(filename, 'r') as tracefile:
        lines = tracefile.readlines()
        meta = ast.literal_eval(lines[0])
        cols = lines[1].rstrip().split('|')
        types = [to_literal] * len(cols)
        for col, t in force_types.items():
            types[cols.index(col)] = t
        pid_idx = cols.index('pid')
        for rec in lines[2:]:
            vals = rec.rstrip().split('|')
            res[int(vals[pid_idx])].append([f(v) for f, v in zip(types, vals)])
    return (meta, {pid: Table(cols, vals) for pid, vals in res.items()})

# signal handler
def signal_ignore(signal, frame):
    print("\nInterrupted\n", file=stderr)

if not args.input_file:
    args.input_file = 'locks.txt'
    if Path(args.input_file).is_file():
        os.rename(args.input_file, args.input_file + '.old')
    script_path = os.path.dirname(os.path.realpath(__file__))
    cmd = [script_path + '/locktrace.py']
    if args.pid:
        cmd += ['-p', str(args.pid)]
    if args.debug:
        cmd += ['-d']
    if args.hist:
        cmd += ['--hist']
    if args.stack_storage_size:
        cmd += ['--stack-storage-size', str(args.stack_storage_size)]
    cmd += [str(args.duration)]
    with open(args.input_file, "w") as outfile:
        p = subprocess.Popen(cmd, stdout=outfile)
        try:
            p_status = p.wait()
        except KeyboardInterrupt:
            p.send_signal(signal.SIGINT)
            p_status = p.wait()
        if p_status != 0:
            print("Profiling failed!")
            exit(1)

force_types = {
    'usr_stack': str, 'usr_syms': str,
    'kernel_stack': str, 'kernel_syms': str,
    'comm': str
}
(meta, stats) = read_tracefile(args.input_file, force_types)
for pid, pid_stats in stats.items():
    if args.pid and pid != args.pid:
        continue
    events = pid_stats
    if args.event == 'lock':
        events = pid_stats.filter('usr_syms', is_not_cond_wait)
    elif args.event == 'cond':
        events = pid_stats.filter('usr_syms', is_cond_wait)

    total_usr = ms_to_s(events.sum_all()['usr_ms'])
    if (total_usr / meta['duration']) == 0:
        if events.count() > 0:
            comm = events.sort('usr_ms')[0]['comm']
            print("Skipping %s: low usr time" % (comm))
        continue

    print("Pid %d: (%d records)" % (pid, pid_stats.count()))
    print_summary_for_pid(pid, pid_stats, meta['duration'])

    syms = 'usr_syms'
    print_stats_for_pid(
        pid, events, args.callstack, syms,
        args.sort_by, args.group_by, args.columns)
