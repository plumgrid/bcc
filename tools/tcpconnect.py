#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcpconnect    Trace TCP connect()s.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpconnect [-h] [-c] [-t] [-p PID [PID ...]] [-P PORT [PORT ...]] [-4 | -6]
#
# All connection attempts are traced, even if they ultimately fail.
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Sep-2015   Brendan Gregg   Created this.
# 14-Feb-2016      "      "     Switch to bpf_perf_output.
# 09-Jan-2019   Takuma Kume     Support filtering by UID
# 30-Jul-2019   Xiaozhou Liu    Count connects.
# 07-Oct-2020   Nabil Schear    Correlate connects with DNS responses
# 08-Mar-2021   Suresh Kumar    Added LPORT option
# 27-Aug-2023   Wu Zhengyang    Trace for PID list.

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
from time import sleep
from datetime import datetime

# arguments
examples = """examples:
    ./tcpconnect             # trace all TCP connect()s
    ./tcpconnect -t          # include timestamps
    ./tcpconnect -d          # include DNS queries associated with connects
    ./tcpconnect -p 181      # only trace PID 180
    ./tcpconnect -p 181,182  # only trace PID 181 and 182
    ./tcpconnect -P 80       # only trace port 80
    ./tcpconnect -P 80,81    # only trace port 80 and 81
    ./tcpconnect -4          # only trace IPv4 family
    ./tcpconnect -6          # only trace IPv6 family
    ./tcpconnect -U          # include UID
    ./tcpconnect -u 1000     # only trace UID 1000
    ./tcpconnect -c          # count connects per src ip and dest ip/port
    ./tcpconnect -L          # include LPORT while printing outputs
    ./tcpconnect --cgroupmap mappath  # only trace cgroups in this BPF map
    ./tcpconnect --mntnsmap mappath   # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Trace TCP connects",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="comma-separated list of PIDs to trace")
parser.add_argument("-P", "--port",
    help="comma-separated list of destination ports to trace.")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
    help="trace IPv6 family only")
parser.add_argument("-L", "--lport", action="store_true",
    help="include LPORT on output")
parser.add_argument("-U", "--print-uid", action="store_true",
    help="include UID on output")
parser.add_argument("-u", "--uid",
    help="trace this UID only")
parser.add_argument("-c", "--count", action="store_true",
    help="count connects per src ip and dest ip/port")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("-d", "--dns", action="store_true",
    help="include likely DNS query associated with each connect")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
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
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

// separate flow keys per address family
struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 dport;
};
BPF_HASH(ipv4_count, struct ipv4_flow_key_t);

struct ipv6_flow_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 dport;
};
BPF_HASH(ipv6_count, struct ipv6_flow_key_t);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    if (container_should_be_filtered()) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID

    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID

    // stash the sock ptr for lookup on return
    currsock.update(&tid, &sk);

    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    struct sock **skpp;
    skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;   // missed entry
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&tid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;

    FILTER_PORT

    FILTER_FAMILY

    if (ipver == 4) {
        IPV4_CODE
    } else /* 6 */ {
        IPV6_CODE
    }

    currsock.delete(&tid);

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}
"""

struct_init = {'ipv4':
        {'count':
               """
               struct ipv4_flow_key_t flow_key = {};
               flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
               flow_key.daddr = skp->__sk_common.skc_daddr;
               flow_key.dport = ntohs(dport);
               ipv4_count.increment(flow_key);""",
          'trace':
               """
               struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
               data4.uid = bpf_get_current_uid_gid();
               data4.ts_us = bpf_ktime_get_ns() / 1000;
               data4.saddr = skp->__sk_common.skc_rcv_saddr;
               data4.daddr = skp->__sk_common.skc_daddr;
               data4.lport = lport;
               data4.dport = ntohs(dport);
               bpf_get_current_comm(&data4.task, sizeof(data4.task));
               ipv4_events.perf_submit(ctx, &data4, sizeof(data4));"""
               },
        'ipv6':
        {'count':
               """
               struct ipv6_flow_key_t flow_key = {};
               bpf_probe_read_kernel(&flow_key.saddr, sizeof(flow_key.saddr),
                   skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
               bpf_probe_read_kernel(&flow_key.daddr, sizeof(flow_key.daddr),
                   skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
               flow_key.dport = ntohs(dport);
               ipv6_count.increment(flow_key);""",
          'trace':
               """
               struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
               data6.uid = bpf_get_current_uid_gid();
               data6.ts_us = bpf_ktime_get_ns() / 1000;
               bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
                   skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
               bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
                   skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
               data6.lport = lport;
               data6.dport = ntohs(dport);
               bpf_get_current_comm(&data6.task, sizeof(data6.task));
               ipv6_events.perf_submit(ctx, &data6, sizeof(data6));"""
               }
               }

# This defines an additional BPF program that instruments udp_recvmsg system
# call to locate DNS response packets on UDP port 53. When these packets are
# located, the data is copied to user-space where python will parse them with
# dnslib.
#
# uses a percpu array of length 1 to store the dns_data_t off the stack to
# allow for a maximum DNS packet length of 512 bytes.
dns_bpf_text = """
#include <net/inet_sock.h>

#define MAX_PKT 512
struct dns_data_t {
    u8  pkt[MAX_PKT];
};

BPF_PERF_OUTPUT(dns_events);

// store msghdr pointer captured on syscall entry to parse on syscall return
BPF_HASH(tbl_udp_msg_hdr, u64, struct msghdr *);

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(dns_data,struct dns_data_t,1);

int trace_udp_recvmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct inet_sock *is = inet_sk(sk);

    // only grab port 53 packets, 13568 is ntohs(53)
    if (is->inet_dport == 13568) {
        struct msghdr *msghdr = (struct msghdr *)PT_REGS_PARM2(ctx);
        tbl_udp_msg_hdr.update(&pid_tgid, &msghdr);
    }
    return 0;
}

int trace_udp_ret_recvmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 zero = 0;
    struct msghdr **msgpp = tbl_udp_msg_hdr.lookup(&pid_tgid);
    if (msgpp == 0)
        return 0;

    struct msghdr *msghdr = (struct msghdr *)*msgpp;
    if (msghdr->msg_iter.TYPE_FIELD != ITER_IOVEC)
        goto delete_and_return;

    int copied = (int)PT_REGS_RC(ctx);
    if (copied < 0)
        goto delete_and_return;
    size_t buflen = (size_t)copied;

    if (buflen > msghdr->msg_iter.iov->iov_len)
        goto delete_and_return;

    if (buflen > MAX_PKT)
        buflen = MAX_PKT;

    struct dns_data_t *data = dns_data.lookup(&zero);
    if (!data) // this should never happen, just making the verifier happy
        return 0;

    void *iovbase = msghdr->msg_iter.iov->iov_base;
    bpf_probe_read(data->pkt, buflen, iovbase);
    dns_events.perf_submit(ctx, data, buflen);

delete_and_return:
    tbl_udp_msg_hdr.delete(&pid_tgid);
    return 0;
}

#include <uapi/linux/udp.h>

int trace_udpv6_recvmsg(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    struct udphdr *hdr = (void*)skb->head + skb->transport_header;
    struct dns_data_t *event;
    int zero = 0;
    void *data;

    /* hex(53) = 0x0035, htons(0x0035) = 0x3500 */
    if (hdr->source != 0x3500)
        return 0;

    /* skip UDP header */
    data = skb->data + 8;

    event = dns_data.lookup(&zero);
    if (!event)
        return 0;

    bpf_probe_read(event->pkt, sizeof(event->pkt), data);
    dns_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}
"""

if args.count and args.dns:
    print("Error: you may not specify -d/--dns with -c/--count.")
    exit()

# code substitutions
if args.count:
    bpf_text = bpf_text.replace("IPV4_CODE", struct_init['ipv4']['count'])
    bpf_text = bpf_text.replace("IPV6_CODE", struct_init['ipv6']['count'])
else:
    bpf_text = bpf_text.replace("IPV4_CODE", struct_init['ipv4']['trace'])
    bpf_text = bpf_text.replace("IPV6_CODE", struct_init['ipv6']['trace'])

if args.pid:
    pids = [int(pid) for pid in args.pid.split(',')]
    pids_if = ' && '.join(['pid != %d' % pid for pid in pids])
    bpf_text = bpf_text.replace('FILTER_PID',
        'if (%s) { return 0; }' % pids_if)
if args.port:
    dports = [int(dport) for dport in args.port.split(',')]
    dports_if = ' && '.join(['dport != %d' % ntohs(dport) for dport in dports])
    bpf_text = bpf_text.replace('FILTER_PORT',
        'if (%s) { currsock.delete(&tid); return 0; }' % dports_if)
if args.ipv4:
    bpf_text = bpf_text.replace('FILTER_FAMILY',
        'if (ipver != 4) { return 0; }')
elif args.ipv6:
    bpf_text = bpf_text.replace('FILTER_FAMILY',
        'if (ipver != 6) { return 0; }')
if args.uid:
    bpf_text = bpf_text.replace('FILTER_UID',
        'if (uid != %s) { return 0; }' % args.uid)
bpf_text = filter_by_containers(args) + bpf_text

bpf_text = bpf_text.replace('FILTER_PID', '')
bpf_text = bpf_text.replace('FILTER_PORT', '')
bpf_text = bpf_text.replace('FILTER_FAMILY', '')
bpf_text = bpf_text.replace('FILTER_UID', '')

if args.dns:
    if BPF.kernel_struct_has_field(b'iov_iter', b'iter_type') == 1:
        dns_bpf_text = dns_bpf_text.replace('TYPE_FIELD', 'iter_type')
    else:
        dns_bpf_text = dns_bpf_text.replace('TYPE_FIELD', 'type')
    bpf_text += dns_bpf_text

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")
    dest_ip = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    if args.lport:
        printb(b"%-7d %-12.12s %-2d %-16s %-6d %-16s %-6d %s" % (event.pid,
            event.task, event.ip,
            inet_ntop(AF_INET, pack("I", event.saddr)).encode(), event.lport,
            dest_ip, event.dport, print_dns(dest_ip)))
    else:
        printb(b"%-7d %-12.12s %-2d %-16s %-16s %-6d %s" % (event.pid,
            event.task, event.ip,
            inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
            dest_ip, event.dport, print_dns(dest_ip)))

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")
    dest_ip = inet_ntop(AF_INET6, event.daddr)
    if args.lport:
        printb(b"%-7d %-12.12s %-2d %-16s %-6d %-16s %-6d %s" % (event.pid,
            event.task, event.ip,
            inet_ntop(AF_INET6, event.saddr).lstrip("::ffff:").encode(), event.lport,
            dest_ip.lstrip("::ffff:").encode(), event.dport, print_dns(dest_ip.encode())))
    else:
        printb(b"%-7d %-12.12s %-2d %-16s %-16s %-6d %s" % (event.pid,
            event.task, event.ip,
            inet_ntop(AF_INET6, event.saddr).lstrip("::ffff:").encode(),
            dest_ip.lstrip("::ffff:").encode(), event.dport, print_dns(dest_ip.encode())))

def depict_cnt(counts_tab, l3prot='ipv4'):
    for k, v in sorted(counts_tab.items(),
                       key=lambda counts: counts[1].value, reverse=True):
        depict_key = ""
        if l3prot == 'ipv4':
            depict_key = "%-25s %-25s %-20s" % \
                         ((inet_ntop(AF_INET, pack('I', k.saddr))),
                          inet_ntop(AF_INET, pack('I', k.daddr)), k.dport)
        else:
            depict_key = "%-25s %-25s %-20s" % \
                         ((inet_ntop(AF_INET6, k.saddr)),
                          inet_ntop(AF_INET6, k.daddr), k.dport)

        print("%s %-10d" % (depict_key, v.value))

def print_dns(dest_ip):
    if not args.dns:
        return b""

    dnsname, timestamp = dns_cache.get(dest_ip, (None, None))
    if timestamp is not None:
        diff = datetime.now() - timestamp
        diff = float(diff.seconds) * 1000 + float(diff.microseconds) / 1000
    else:
        diff = 0
    if dnsname is None:
        dnsname = b"No DNS Query"
        if dest_ip == b"127.0.0.1" or dest_ip == b"::1":
            dnsname = b"localhost"
    retval = b"%s" % dnsname
    if diff > DELAY_DNS:
        retval += b" (%.3fms)" % diff
    return retval

if args.dns:
    try:
        import dnslib
        from cachetools import TTLCache
    except ImportError:
        print("Error: The python packages dnslib and cachetools are required "
                "to use the -d/--dns option.")
        print("Install this package with:")
        print("\t$ pip3 install dnslib cachetools")
        print("   or")
        print("\t$ sudo apt-get install python3-dnslib python3-cachetools "
              "(on Ubuntu 18.04+)")
        exit(1)

    # 24 hours
    DEFAULT_TTL = 86400

    # Cache Size in entries
    DNS_CACHE_SIZE = 10240

    # delay in ms in which to warn users of long delay between the query
    # and the connect that used the IP
    DELAY_DNS = 100

    dns_cache = TTLCache(maxsize=DNS_CACHE_SIZE, ttl=DEFAULT_TTL)

    # process event
    def save_dns(cpu, data, size):
        event = b["dns_events"].event(data)
        payload = event.pkt[:size]

        # pass the payload to dnslib for parsing
        dnspkt = dnslib.DNSRecord.parse(payload)
        # lets only look at responses
        if dnspkt.header.qr != 1:
            return
        # must be some questions in there
        if dnspkt.header.q != 1:
            return
        # make sure there are answers
        if dnspkt.header.a == 0 and dnspkt.header.aa == 0:
            return

        # lop off the trailing .
        question = ("%s" % dnspkt.q.qname)[:-1].encode('utf-8')

        for answer in dnspkt.rr:
            # skip all but A and AAAA records
            if answer.rtype == 1 or answer.rtype == 28:
                dns_cache[str(answer.rdata).encode('utf-8')] = (question,
                                                              datetime.now())

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")
if args.dns:
    b.attach_kprobe(event="udp_recvmsg", fn_name="trace_udp_recvmsg")
    b.attach_kretprobe(event="udp_recvmsg", fn_name="trace_udp_ret_recvmsg")
    b.attach_kprobe(event="udpv6_queue_rcv_one_skb", fn_name="trace_udpv6_recvmsg")

print("Tracing connect ... Hit Ctrl-C to end")
if args.count:
    try:
        while True:
            sleep(99999999)
    except KeyboardInterrupt:
        pass

    # header
    print("\n%-25s %-25s %-20s %-10s" % (
        "LADDR", "RADDR", "RPORT", "CONNECTS"))
    depict_cnt(b["ipv4_count"])
    depict_cnt(b["ipv6_count"], l3prot='ipv6')
# read events
else:
    # header
    if args.timestamp:
        print("%-9s" % ("TIME(s)"), end="")
    if args.print_uid:
        print("%-6s" % ("UID"), end="")
    if args.lport:
        print("%-7s %-12s %-2s %-16s %-6s %-16s %-6s" % ("PID", "COMM", "IP", "SADDR",
            "LPORT", "DADDR", "DPORT"), end="")
    else:
        print("%-7s %-12s %-2s %-16s %-16s %-6s" % ("PID", "COMM", "IP", "SADDR",
            "DADDR", "DPORT"), end="")
    if args.dns:
        print(" QUERY")
    else:
        print()

    start_ts = 0

    # read events
    b["ipv4_events"].open_perf_buffer(print_ipv4_event)
    b["ipv6_events"].open_perf_buffer(print_ipv6_event)
    if args.dns:
        b["dns_events"].open_perf_buffer(save_dns)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
