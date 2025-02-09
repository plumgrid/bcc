#!/usr/bin/env python3
#
# mariadb_query_io  Show I/O information about queries.
#
# USAGE: mariadb_query_io $(pidof mariadbd)
#
# Copyright 2024 IONOS SE
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Author: Max Kellermann <max.kellermann@ionos.com>

# Columns:
#
# time: the wallclock time
# pid: the process/thread id
# db: the current MariaDB database name
# duration: the total duration of the query
# sys_t: the total time of all system calls while processing this query
# n_sys: the number of system calls
# futex_t: the total time of all futex system calls
# futex_addr: the address of the slowest futex
# r_t: total time reading (may include pipes)
# r_b: total bytes read
# w_t: total time writing (may include pipes)
# w_b: total bytes written
# sync_t: total time waiting for fsync(), fdatasync()
# send_t: total time sending to sockets
# send_b: total bytes sent to sockets
# young: number of "made_young" in the MariaDB buffer
# query: the query text (SQL)
#
# All durations are wallclock.

from bcc import BPF
from datetime import datetime
import ctypes
import sys

if len(sys.argv) < 2:
    print("USAGE: mariadb_slow_queries.py PID", file=sys.stderr)
    sys.exit(1)

pid = int(sys.argv[1])

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

/**
 * Per-process data for BPF_HASH(processes).
 */
struct process_data {
    /** the name of the current database */
    char db[16];
};

struct io_data {
    u64 bytes;
    u64 duration_ns;
    u64 since_ns;
    unsigned count;
};

static void io_data_begin(struct io_data *data)
{
    data->since_ns = bpf_ktime_get_ns();
}

static void io_data_end(struct io_data *data, s64 bytes)
{
    if (bytes > 0)
        data->bytes += bytes;
    data->duration_ns += bpf_ktime_get_ns() - data->since_ns;;
    ++data->count;
}

/**
 * Per-query data for BPF_HASH(queries).
 */
struct data {
    u64 start_time_ns, end_time_ns;
    u64 futex_duration_ns;
    u64 futex_since_ns;
    u64 futex_current_address, futex_max_address, futex_max_duration;
    struct io_data read, write, sync, send;
    u64 sys_since_ns, sys_duration_ns;
    unsigned nlocked;
    unsigned n_sys;
    unsigned n_make_young;
    u32 pid;
    char query[100];
    struct process_data process;
};

BPF_HASH(processes, u32, struct process_data);
BPF_HASH(queries, u32, struct data);
BPF_PERF_OUTPUT(events);

int alloc_query(struct pt_regs *ctx, void* thd, char* query, size_t len) {
    if (query) {
        u32 pid = bpf_get_current_pid_tgid();
        struct data data = {};
    
        data.start_time_ns = bpf_ktime_get_ns();
        data.pid = pid;
    
        bpf_probe_read_str(&data.query, sizeof(data.query), query);
    
        struct process_data *process = processes.lookup(&pid);
        if (process)
            data.process = *process;
    
        queries.update(&pid, &data);
    }
    return 0;
};

int do_command_ret(struct pt_regs *ctx, void *thd, bool blocking) {
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        data->end_time_ns = bpf_ktime_get_ns();
        if (data->end_time_ns - data->start_time_ns >= 10000000) {
            events.perf_submit(ctx, data, sizeof(*data));
        }
        queries.delete(&pid);
    }
    return 0;
};

int buf_page_make_young(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        ++data->n_make_young;
    }
    return 0;
};

struct st_mysql_const_lex_string
{
    const char *str;
    size_t length;
};
typedef struct st_mysql_const_lex_string LEX_CSTRING;
int mysql_change_db(struct pt_regs *ctx, void *thd, const LEX_CSTRING *new_db_name, bool force_switch) {
    u32 pid = bpf_get_current_pid_tgid();
    struct process_data data = {};
    bpf_probe_read_str(&data.db, sizeof(data.db), new_db_name->str);
    processes.update(&pid, &data);
    return 0;
};

TRACEPOINT_PROBE(syscalls, sys_enter_futex)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        data->futex_since_ns = bpf_ktime_get_ns();
        data->futex_current_address = (u64)args->uaddr;
    }
    return 0;
};

TRACEPOINT_PROBE(syscalls, sys_exit_futex)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        u64 duration = bpf_ktime_get_ns() - data->futex_since_ns;
        data->futex_duration_ns += duration;
        if (duration > data->futex_max_duration) {
            data->futex_max_duration = duration;
            data->futex_max_address = data->futex_current_address;
        }
    }
    return 0;
};

static int trace_read_entry()
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        io_data_begin(&data->read);
    }
    return 0;
}

static int trace_read_return(ssize_t nbytes)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        io_data_end(&data->read, nbytes);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pread64) { return trace_read_entry(); }
TRACEPOINT_PROBE(syscalls, sys_exit_pread64) { return trace_read_return(args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_preadv) { return trace_read_entry(); }
TRACEPOINT_PROBE(syscalls, sys_exit_preadv) { return trace_read_return(args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_preadv2) { return trace_read_entry(); }
TRACEPOINT_PROBE(syscalls, sys_exit_preadv2) { return trace_read_return(args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_read) { return trace_read_entry(); }
TRACEPOINT_PROBE(syscalls, sys_exit_read) { return trace_read_return(args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_readv) { return trace_read_entry(); }
TRACEPOINT_PROBE(syscalls, sys_exit_readv) { return trace_read_return(args->ret); }

static int trace_write_entry()
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        io_data_begin(&data->write);
    }
    return 0;
}

static int trace_write_return(ssize_t nbytes)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        io_data_end(&data->write, nbytes);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) { return trace_write_entry(); }
TRACEPOINT_PROBE(syscalls, sys_exit_pwrite64) { return trace_write_return(args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_pwritev) { return trace_write_entry(); }
TRACEPOINT_PROBE(syscalls, sys_exit_pwritev) { return trace_write_return(args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_pwritev2) { return trace_write_entry(); }
TRACEPOINT_PROBE(syscalls, sys_exit_pwritev2) { return trace_write_return(args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_write) { return trace_write_entry(); }
TRACEPOINT_PROBE(syscalls, sys_exit_write) { return trace_write_return(args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_writev) { return trace_write_entry(); }
TRACEPOINT_PROBE(syscalls, sys_exit_writev) { return trace_write_return(args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_fdatasync)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        io_data_begin(&data->sync);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fdatasync)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        io_data_end(&data->sync, 0);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        io_data_begin(&data->send);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        ssize_t nbytes = args->ret;
        io_data_end(&data->send, nbytes);
    }
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        data->sys_since_ns = bpf_ktime_get_ns();
        ++data->n_sys;
    }
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct data *data = queries.lookup(&pid);
    if (data) {
        data->sys_duration_ns += bpf_ktime_get_ns() - data->sys_since_ns;
    }
    return 0;
}
""")

b.attach_uprobe(name="/usr/sbin/mariadbd", sym="_Z11alloc_queryP3THDPKcm", fn_name="alloc_query", pid=pid)
b.attach_uretprobe(name="/usr/sbin/mariadbd", sym="_Z10do_commandP3THDb", fn_name="do_command_ret", pid=pid)
b.attach_uprobe(name="/usr/sbin/mariadbd", sym="_Z19buf_page_make_youngP10buf_page_t", fn_name="buf_page_make_young", pid=pid)

# uint mysql_change_db(THD *thd, const LEX_CSTRING *new_db_name, bool force_switch)
b.attach_uprobe(name="/usr/sbin/mariadbd", sym="_Z15mysql_change_dbP3THDPK25st_mysql_const_lex_stringb", fn_name="mysql_change_db", pid=pid)

#b.attach_uprobe(name="/usr/sbin/mariadbd", sym="_Z11alloc_queryP3THDPKcm", fn_name="do_command", pid=pid)

class IOData(ctypes.Structure):
    _fields_ = [
        ("bytes", ctypes.c_ulonglong),
        ("duration_ns", ctypes.c_ulonglong),
        ("since_ns", ctypes.c_ulonglong),
        ("count", ctypes.c_uint),
    ]

class ProcessData(ctypes.Structure):
    _fields_ = [
        ("db", ctypes.c_char * 16),
    ]

class Data(ctypes.Structure):
    _fields_ = [
        ("start_time_ns", ctypes.c_ulonglong),
        ("end_time_ns", ctypes.c_ulonglong),
        ("futex_duration_ns", ctypes.c_ulonglong),
        ("futex_since_ns", ctypes.c_ulonglong),
        ("futex_current_address", ctypes.c_ulonglong),
        ("futex_max_address", ctypes.c_ulonglong),
        ("futex_max_duration", ctypes.c_ulonglong),
        ("read", IOData),
        ("write", IOData),
        ("sync", IOData),
        ("send", IOData),
        ("sys_since_ns", ctypes.c_ulonglong),
        ("sys_duration_ns", ctypes.c_ulonglong),
        ("nlocked", ctypes.c_uint),
        ("n_sys", ctypes.c_uint),
        ("n_make_young", ctypes.c_uint),
        ("pid", ctypes.c_uint),
        ("query", ctypes.c_char * 100),
        ("process", ProcessData),
    ]

print("%-12s %6s %-12s %10s "
      "%8s %5s "
      "%8s %14s "
      "%8s %7s "
      "%8s %7s "
      "%8s "
      "%8s %8s "
      "%6s %s" % (
    'time', 'pid', 'db', 'duration',
    'sys_t', 'n_sys',
    'futex_t', 'futex_addr',
    'r_t', 'r_b',
    'w_t', 'w_b',
    'sync_t',
    'send_t', 'send_b',
    'young', 'query',
))

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    print("%-12s %6d %12s %8dms "
          "%6dms %5d "
          "%6dms %14x "
          "%6dms %7d "
          "%6dms %7d "
          "%6dms "
          "%6dms %8d "
          "%6d %s" % (
        datetime.utcnow().isoformat(timespec='milliseconds').split('T')[1], event.pid, event.process.db.decode('ascii', errors='replace'),
        (event.end_time_ns - event.start_time_ns) // 1000000,
        event.sys_duration_ns // 1000000, event.n_sys,
        event.futex_duration_ns // 1000000,
        event.futex_max_address,
        event.read.duration_ns // 1000000, event.read.bytes,
        event.write.duration_ns // 1000000, event.write.bytes,
        event.sync.duration_ns // 1000000,
        event.send.duration_ns // 1000000,
        event.send.bytes,
        event.n_make_young,
        event.query
    ))

b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.kprobe_poll()
