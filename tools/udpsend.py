#!/usr/bin/env python3
# coding:utf-8
#
# udpsend    Trace UDP sendmsg()s.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: udpsend [-h] [-t]
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Jan-2024   Zhixiong Wei   Created this.

from bcc import BPF
from bcc.utils import printb
from socket import inet_ntop, AF_INET, AF_INET6, ntohs
from struct import pack
import argparse
from time import strftime

# arguments
examples = """examples:
    ./udpsend           # trace all UDP sendmsg()s
    ./udpsend -t        # include timestamps
"""
parser = argparse.ArgumentParser(
    description="Trace UDP sends",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--time", action="store_true",
    help="include time column on output (HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
args = parser.parse_args()


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 sport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 sport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u16 family = 0, sport = 0, dport;
    family = sk->__sk_common.skc_family;
    sport = sk->__sk_common.skc_num;
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = 4};
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.sport = sport;
        data4.dport = dport;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid = pid, .ip = 6};
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.sport = sport;
        data6.dport = dport;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    // else drop
        
    return 0;
}
"""


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
        inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        event.sport,
        inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
        ntohs(event.dport)))


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
        inet_ntop(AF_INET6, event.saddr).encode(),
        event.sport,
        inet_ntop(AF_INET6, event.daddr).encode(),
        ntohs(event.dport)))


# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="udpv6_queue_rcv_one_skb", fn_name="kprobe__udp_sendmsg")

print("Tracing UDP sendmsg ... Hit Ctrl-C to end")

if args.time:
    print("%-9s" % ("TIME"), end="")
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
# header
print("%-7s %-12s %-2s %-16s %-5s %-16s %-5s" % ("PID", "COMM", "IP", "SADDR",
    "SPORT", "DADDR", "DPORT"))

start_ts = 0

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
