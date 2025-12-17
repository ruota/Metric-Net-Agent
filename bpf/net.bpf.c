// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef AF_INET
#define AF_INET 2
#endif

struct event {
    __u64 sk;
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  family;
    __u8  proto; // IPPROTO_TCP or IPPROTO_UDP
    __u8  op;    // 1=connect, 2=tx duration
    __u8  _pad;
    __u64 duration_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    // 4 KiB ring buffer (page aligned) to fit under low memlock limits.
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);   // sk pointer
    __type(value, __u64); // start ts ns
} start_ts SEC(".maps");

#define OP_CONNECT 1
#define OP_TX_DURATION 2

static __always_inline void set_start_ts(struct sock *sk) {
    __u64 key = (__u64)sk;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ts, &key, &ts, BPF_ANY);
}

static __always_inline int submit_event(struct event *e) {
    struct event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) {
        return 0;
    }
    __builtin_memcpy(out, e, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
    return 0;
}

// kprobe: tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(on_tcp_v4_connect, struct sock *sk)
{
    if (!sk) {
        return 0;
    }

    struct event e = {};

    e.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e.sk = (__u64)sk;
    e.proto = IPPROTO_TCP;
    e.family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e.op = OP_CONNECT;
    e.sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    // sk fields are in network order for ports
    e.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    return submit_event(&e);
}

// kprobe: udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(on_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk) {
        return 0;
    }

    struct event e = {};

    e.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e.sk = (__u64)sk;
    e.proto = IPPROTO_UDP;
    e.family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e.op = OP_CONNECT;
    e.sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    __u16 dport = 0;
    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    const struct sockaddr_in *user_sin = NULL;
    if (msg) {
        user_sin = BPF_CORE_READ(msg, msg_name);
    }
    struct sockaddr_in sin = {};
    if (user_sin) {
        bpf_probe_read_user(&sin, sizeof(sin), user_sin);
        if (sin.sin_family == AF_INET) {
            dport = sin.sin_port;
            daddr = sin.sin_addr.s_addr;
            e.family = AF_INET;
        }
    }

    if (dport == 0) {
        dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    }

    e.saddr = saddr;
    e.daddr = daddr;
    e.dport = bpf_ntohs(dport);

    set_start_ts(sk);
    submit_event(&e);
    return 0;
}

// kprobe: tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(on_tcp_sendmsg, struct sock *sk)
{
    if (!sk) {
        return 0;
    }
    set_start_ts(sk);
    return 0;
}

static __always_inline int emit_duration(struct sock *sk, __u8 proto)
{
    __u64 key = (__u64)sk;
    __u64 *start = bpf_map_lookup_elem(&start_ts, &key);
    if (!start) {
        return 0;
    }
    __u64 now = bpf_ktime_get_ns();
    __u64 dur = now - *start;
    bpf_map_delete_elem(&start_ts, &key);

    struct event e = {};
    e.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e.proto = proto;
    e.family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e.op = OP_TX_DURATION;
    e.duration_ns = dur;
    e.sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    e.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    return submit_event(&e);
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(on_tcp_recvmsg, struct sock *sk)
{
    if (!sk) {
        return 0;
    }
    return emit_duration(sk, IPPROTO_TCP);
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(on_udp_recvmsg, struct sock *sk)
{
    if (!sk) {
        return 0;
    }
    return emit_duration(sk, IPPROTO_UDP);
}

char LICENSE[] SEC("license") = "GPL";
