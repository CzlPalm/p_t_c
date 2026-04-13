// SPDX-License-Identifier: GPL-2.0
/* fd_tracker.bpf.c — v4 (保持 v3 已验证的 connect 追踪) */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fd_tracker.h"

char LICENSE[] SEC("license") = "GPL";

struct connect_args {
    __u64 addr_ptr;
    __u32 addrlen;
    __u32 fd;
    __u32 pid;
};

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, __u64); __type(value, struct connect_args);
} pending SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256*1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct connect_args a = {
        .addr_ptr = ctx->args[1],
        .addrlen  = (__u32)ctx->args[2],
        .fd       = (__u32)ctx->args[0],
        .pid      = (__u32)(pid_tgid >> 32),
    };
    bpf_map_update_elem(&pending, &pid_tgid, &a, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int exit_connect(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret != 0 && ret != -115) goto out;

    __u64 tid = bpf_get_current_pid_tgid();
    struct connect_args *a = bpf_map_lookup_elem(&pending, &tid);
    if (!a) return 0;

    __u16 family = 0;
    bpf_probe_read_user(&family, 2, (void *)a->addr_ptr);
    if (family != 2) goto out;  /* AF_INET only */

    __u16 port_be = 0;
    __u32 addr = 0;
    bpf_probe_read_user(&port_be, 2, (void *)(a->addr_ptr + 2));
    bpf_probe_read_user(&addr,    4, (void *)(a->addr_ptr + 4));

    __u16 port = __builtin_bswap16(port_be);
    if (port != 443) goto out;

    struct connect_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) goto out;

    evt->pid      = a->pid;
    evt->tid      = (__u32)tid;
    evt->ts_ns    = bpf_ktime_get_ns();
    evt->fd       = a->fd;
    evt->dst_ip   = addr;
    evt->dst_port = port;
    bpf_ringbuf_submit(evt, 0);

out:
    bpf_map_delete_elem(&pending, &tid);
    return 0;
}
