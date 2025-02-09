// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "tcptop.h"

/* Taken from kernel include/linux/socket.h. */
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct filter_cfg_t);
} filter_cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_key_t);
	__type(value, struct traffic_t);
} ip_map SEC(".maps");

static int probe_ip(bool receiving, struct sock *sk, size_t size)
{
	int zero = 0;
	struct filter_cfg_t *args = bpf_map_lookup_elem(&filter_cfg_map, &zero);
	if (!args)
		return 0;

	struct ip_key_t ip_key = {};
	struct traffic_t *trafficp;
	u16 family;
	u32 pid;

	if (args->filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (args->target_pid != -1 && args->target_pid != pid)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (args->target_family != -1 && args->target_family != family)
		return 0;

	/* drop */
	if (family != AF_INET && family != AF_INET6)
		return 0;

	ip_key.pid = pid;
	bpf_get_current_comm(&ip_key.name, sizeof(ip_key.name));
	ip_key.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	ip_key.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	ip_key.family = family;

	if (family == AF_INET) {
		bpf_probe_read_kernel(&ip_key.saddr,
				      sizeof(sk->__sk_common.skc_rcv_saddr),
				      &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read_kernel(&ip_key.daddr,
				      sizeof(sk->__sk_common.skc_daddr),
				      &sk->__sk_common.skc_daddr);
	} else {
		/*
		 * family == AF_INET6,
		 * we already checked above family is correct.
		 */
		bpf_probe_read_kernel(&ip_key.saddr,
				      sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
				      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(&ip_key.daddr,
				      sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
				      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
	if (!trafficp) {
		struct traffic_t zero;

		if (receiving) {
			zero.sent = 0;
			zero.received = size;
		} else {
			zero.sent = size;
			zero.received = 0;
		}

		bpf_map_update_elem(&ip_map, &ip_key, &zero, BPF_NOEXIST);
	} else {
		if (receiving)
			trafficp->received += size;
		else
			trafficp->sent += size;

		bpf_map_update_elem(&ip_map, &ip_key, trafficp, BPF_EXIST);
	}

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	return probe_ip(false, sk, size);
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;

	return probe_ip(true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";
