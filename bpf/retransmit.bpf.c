// SPDX-License-Identifier: GPL-2.0
//
// retransmit.bpf.c — TCP 再送イベントを kprobe で取得し Ring Buffer に書き込む
//
// フック対象:
//   tcp_retransmit_skb      通常再送 (タイムアウト / SACK)
//   tcp_fastretrans_alert   高速再送 (dupACK x3)
//   tcp_receive_reset       RST 受信
//
// 動作カーネル: Linux 6.0+
// コンパイル:   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//               -I vmlinux/ -c retransmit.bpf.c -o retransmit.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "retransmit.h"

/* ------------------------------------------------------------------ */
/* Ring Buffer マップ                                                   */
/* ------------------------------------------------------------------ */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} events SEC(".maps");

/* ------------------------------------------------------------------ */
/* ヘルパー: sock から共通フィールドを retransmit_event に詰める         */
/* ------------------------------------------------------------------ */
static __always_inline void fill_event(struct retransmit_event *e,
                                       struct sock *sk,
                                       __u8 type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e->timestamp_ns  = bpf_ktime_get_ns();
    e->pid           = pid_tgid >> 32;          /* tgid = ユーザー空間の PID */
    e->retrans_type  = type;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    /* CO-RE でカーネル構造体フィールドを安全に読む */
    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);          /* host byte order */
    e->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);        /* network byte order */

    __builtin_memset(e->pad, 0, sizeof(e->pad));
}

/* ------------------------------------------------------------------ */
/* kprobe: tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)    */
/* 通常再送 (RTO タイムアウト / SACK)                                   */
/* ------------------------------------------------------------------ */
SEC("tracepoint/tcp/tcp_retransmit_skb")
int handle_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    struct retransmit_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_event(e, sk, RETRANS_TYPE_TIMEOUT);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------------------------------------------------------------ */
/* kprobe: tcp_fastretrans_alert                                        */
/* シグネチャ: void tcp_fastretrans_alert(struct sock *sk, ...)         */
/* ------------------------------------------------------------------ */
SEC("tracepoint/tcp/tcp_fastretrans")
int handle_tcp_fastretrans_alert(struct trace_event_raw_tcp_event_sk *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    struct retransmit_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_event(e, sk, RETRANS_TYPE_FAST);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ------------------------------------------------------------------ */
/* kprobe: tcp_receive_reset                                            */
/* シグネチャ: void tcp_receive_reset(struct sock *sk)                  */
/* ------------------------------------------------------------------ */
SEC("tracepoint/tcp/tcp_receive_reset")
int handle_tcp_receive_reset(struct trace_event_raw_tcp_event_sk *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    struct retransmit_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_event(e, sk, RETRANS_TYPE_RESET);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
