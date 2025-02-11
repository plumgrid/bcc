// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Yusheng Zheng
//
// Based on sslsniff from BCC by Adrian Lopez & Mark Drayton.
// 15-Aug-2023   Yusheng Zheng   Created this.
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "sslsniff.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} perf_SSL_events SEC(".maps");

#define BASE_EVENT_SIZE ((size_t)(&((struct probe_SSL_data_t *)0)->buf))
#define EVENT_SIZE(X) (BASE_EVENT_SIZE + ((size_t)(X)))
#define MAX_ENTRIES 10240

#define min(x, y)                      \
    ({                                 \
        typeof(x) _min1 = (x);         \
        typeof(y) _min2 = (y);         \
        (void)(&_min1 == &_min2);      \
        _min1 < _min2 ? _min1 : _min2; \
    })

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct probe_SSL_data_t);
} ssl_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} start_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} bufs SEC(".maps");

const volatile pid_t targ_pid = 0;
const volatile uid_t targ_uid = -1;

static __always_inline bool trace_allowed(u32 uid, u32 pid)
{
    /* filters */
    if (targ_pid && targ_pid != pid)
        return false;
    if (targ_uid != -1) {
        if (targ_uid != uid) {
            return false;
        }
    }
    return true;
}

SEC("uprobe/do_handshake")
int BPF_UPROBE(probe_SSL_rw_enter, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();

    if (!trace_allowed(uid, pid)) {
        return 0;
    }

    /* store arg info for later lookup */
    bpf_map_update_elem(&bufs, &tid, &buf, BPF_ANY);
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);
    return 0;
}

static int SSL_exit(struct pt_regs *ctx, int rw) {
    int ret = 0;
    u32 zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();

    if (!trace_allowed(uid, pid)) {
        return 0;
    }

    /* store arg info for later lookup */
    u64 *bufp = bpf_map_lookup_elem(&bufs, &tid);
    if (bufp == 0)
        return 0;

    u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (!tsp)
        return 0;
    u64 delta_ns = ts - *tsp;

    int len = PT_REGS_RC(ctx);
    if (len <= 0)  // no data
        return 0;

    struct probe_SSL_data_t *data = bpf_map_lookup_elem(&ssl_data, &zero);
    if (!data)
        return 0;

    data->timestamp_ns = ts;
    data->delta_ns = delta_ns;
    data->pid = pid;
    data->tid = tid;
    data->uid = uid;
    data->len = (u32)len;
    data->buf_filled = 0;
    data->rw = rw;
    data->is_handshake = false;
    u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)len);

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    if (bufp != 0)
        ret = bpf_probe_read_user(&data->buf, buf_copy_size, (char *)*bufp);

    bpf_map_delete_elem(&bufs, &tid);
    bpf_map_delete_elem(&start_ns, &tid);

    if (!ret)
        data->buf_filled = 1;
    else
        buf_copy_size = 0;

    bpf_perf_event_output(ctx, &perf_SSL_events, BPF_F_CURRENT_CPU, data,
                            EVENT_SIZE(buf_copy_size));
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(probe_SSL_read_exit) {
    return (SSL_exit(ctx, 0));
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(probe_SSL_write_exit) {
    return (SSL_exit(ctx, 1));
}

SEC("uprobe/do_handshake")
int BPF_UPROBE(probe_SSL_do_handshake_enter, void *ssl) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u64 ts = bpf_ktime_get_ns();
    u32 uid = bpf_get_current_uid_gid();

    if (!trace_allowed(uid, pid)) {
        return 0;
    }

    /* store arg info for later lookup */
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("uretprobe/do_handshake")
int BPF_URETPROBE(probe_SSL_do_handshake_exit) {
    u32 zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();
    int ret = 0;

    /* use kernel terminology here for tgid/pid: */
    u32 tgid = pid_tgid >> 32;

    /* store arg info for later lookup */
    if (!trace_allowed(tgid, pid)) {
        return 0;
    }

    u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (tsp == 0)
        return 0;

    ret = PT_REGS_RC(ctx);
    if (ret <= 0)  // handshake failed
        return 0;

    struct probe_SSL_data_t *data = bpf_map_lookup_elem(&ssl_data, &zero);
    if (!data)
        return 0;

    data->timestamp_ns = ts;
    data->delta_ns = ts - *tsp;
    data->pid = pid;
    data->tid = tid;
    data->uid = uid;
    data->len = ret;
    data->buf_filled = 0;
    data->rw = 2;
    data->is_handshake = true;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_map_delete_elem(&start_ns, &tid);

    bpf_perf_event_output(ctx, &perf_SSL_events, BPF_F_CURRENT_CPU, data,
                            EVENT_SIZE(0));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
