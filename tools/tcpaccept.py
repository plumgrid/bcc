#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcpaccept Trace TCP accept()s.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpaccept [-h] [-T] [-t] [-p PID [PID ...]] [-P PORT [PORT ...]] [-4 | -6]
#
# This uses dynamic tracing of the kernel inet_csk_accept() socket function
# (from tcp_prot.accept), and will need to be modified to match kernel changes.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Oct-2015   Brendan Gregg   Created this.
# 14-Feb-2016      "      "     Switch to bpf_perf_output.
# 27-Aug-2023   Wu Zhengyang    Trace for PID list.

from __future__ import print_function
from bcc.containers import filter_by_containers
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse
from bcc.utils import printb
from time import strftime

# arguments
examples = """examples:
    ./tcpaccept             # trace all TCP accept()s
    ./tcpaccept -t          # include timestamps
    ./tcpaccept -p 181      # only trace PID 181
    ./tcpaccept -p 181,182  # only trace PID 181 and 182
    ./tcpaccept -P 80       # only trace port 80
    ./tcpaccept -P 80,81    # only trace port 80 and 81
    ./tcpaccept --cgroupmap mappath  # only trace cgroups in this BPF map
    ./tcpaccept --mntnsmap mappath   # only trace mount namespaces in the map
    ./tcpaccept -4          # trace IPv4 family only
    ./tcpaccept -6          # trace IPv6 family only
"""
parser = argparse.ArgumentParser(
    description="Trace TCP accepts",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--time", action="store_true",
    help="include time column on output (HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="comma-separated list of PIDs to trace")
parser.add_argument("-P", "--port",
    help="comma-separated list of local ports to trace")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
    help="trace IPv6 family only")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);
"""

#
# The following code uses kprobes to instrument inet_csk_accept().
# On Linux 4.16 and later, we could use sock:inet_sock_set_state
# tracepoint for efficiency, but it may output wrong PIDs. This is
# because sock:inet_sock_set_state may run outside of process context.
# Hence, we stick to kprobes until we find a proper solution.
#
bpf_text_kprobe = """
int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    if (container_should_be_filtered()) {
        return 0;
    }

    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    ##FILTER_PID##

    if (newsk == NULL)
        return 0;

    // check this is TCP
    u16 protocol = 0;
    // workaround for reading the sk_protocol bitfield:

    // Following comments add by Joe Yin:
    // Unfortunately,it can not work since Linux 4.10,
    // because the sk_wmem_queued is not following the bitfield of sk_protocol.
    // And the following member is sk_gso_max_segs.
    // So, we can use this:
    // bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&newsk->sk_gso_max_segs) - 3);
    // In order to  diff the pre-4.10 and 4.10+ ,introduce the variables gso_max_segs_offset,sk_lingertime,
    // sk_lingertime is closed to the gso_max_segs_offset,and
    // the offset between the two members is 4

    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);


    // Since kernel v5.6 sk_protocol is its own u16 field and gso_max_segs
    // precedes sk_lingertime.
    if (sk_lingertime_offset - gso_max_segs_offset == 2)
        protocol = newsk->sk_protocol;
    else if (sk_lingertime_offset - gso_max_segs_offset == 4)
        // 4.10+ with little endian
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 3);
    else
        // pre-4.10 with little endian
        protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 3);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        // 4.10+ with big endian
        protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 1);
    else
        // pre-4.10 with big endian
        protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 1);
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

    if (protocol != IPPROTO_TCP)
        return 0;

    // pull in details
    u16 family = 0, lport = 0, dport;
    family = newsk->__sk_common.skc_family;
    lport = newsk->__sk_common.skc_num;
    dport = newsk->__sk_common.skc_dport;
    dport = ntohs(dport);

    ##FILTER_FAMILY##

    ##FILTER_PORT##

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = 4};
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = newsk->__sk_common.skc_rcv_saddr;
        data4.daddr = newsk->__sk_common.skc_daddr;
        data4.lport = lport;
        data4.dport = dport;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid = pid, .ip = 6};
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
            &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
            &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.lport = lport;
        data6.dport = dport;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    // else drop

    return 0;
}
"""

bpf_text += bpf_text_kprobe

# code substitutions
if args.pid:
    pids = [int(pid) for pid in args.pid.split(',')]
    pids_if = ' && '.join(['pid != %d' % pid for pid in pids])
    bpf_text = bpf_text.replace('##FILTER_PID##',
        'if (%s) { return 0; }' % pids_if)
else:
    bpf_text = bpf_text.replace('##FILTER_PID##', '')
if args.port:
    lports = [int(lport) for lport in args.port.split(',')]
    lports_if = ' && '.join(['lport != %d' % lport for lport in lports])
    bpf_text = bpf_text.replace('##FILTER_PORT##',
        'if (%s) { return 0; }' % lports_if)
if args.ipv4:
    bpf_text = bpf_text.replace('##FILTER_FAMILY##',
        'if (family != AF_INET) { return 0; }')
elif args.ipv6:
    bpf_text = bpf_text.replace('##FILTER_FAMILY##',
        'if (family != AF_INET6) { return 0; }')

bpf_text = filter_by_containers(args) + bpf_text
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

bpf_text = bpf_text.replace('##FILTER_PORT##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY##', '')

# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    global start_ts
    if args.time:
        printb(b"%-9s" % strftime("%H:%M:%S").encode('ascii'), nl="")
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    printb(b"%-7d %-12.12s %-2d %-16s %-5d %-16s %-5d" % (event.pid,
        event.task, event.ip,
        inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
        event.dport,
        inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        event.lport))

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    global start_ts
    if args.time:
        printb(b"%-9s" % strftime("%H:%M:%S").encode('ascii'), nl="")
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    printb(b"%-7d %-12.12s %-2d %-16s %-5d %-16s %-5d" % (event.pid,
        event.task, event.ip,
        inet_ntop(AF_INET6, event.daddr).lstrip("::ffff:").encode(),
        event.dport,
        inet_ntop(AF_INET6, event.saddr).lstrip("::ffff:").encode(),
        event.lport))

# initialize BPF
b = BPF(text=bpf_text)

# header
if args.time:
    print("%-9s" % ("TIME"), end="")
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
print("%-7s %-12s %-2s %-16s %-5s %-16s %-5s" % ("PID", "COMM", "IP", "RADDR",
    "RPORT", "LADDR", "LPORT"))

start_ts = 0

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
