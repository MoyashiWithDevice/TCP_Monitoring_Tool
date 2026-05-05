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

/* カーネル → ユーザーランド 転送イベント構造体
 * Go 側の RetransmitEvent と必ずレイアウトを一致させること。
 * __attribute__((packed)) は使わず、手動でパディングを入れる。
 */
typedef struct retransmit_event {
    __u64 timestamp_ns;   /* bpf_ktime_get_ns() */
    __u32 pid;            /* tgid (ユーザーから見た PID) */
    __u8  comm[16];       /* プロセス名 (最大 15 文字 + NUL) */
    __u32 saddr;          /* 送信元 IPv4 アドレス (ネットワークバイトオーダー) */
    __u32 daddr;          /* 宛先   IPv4 アドレス (ネットワークバイトオーダー) */
    __u16 sport;          /* 送信元ポート (ホストバイトオーダー) */
    __u16 dport;          /* 宛先   ポート (ネットワークバイトオーダー → 読み取り時に変換) */
    __u8  retrans_type;   /* RETRANS_TYPE_* */
    __u8  pad[3];         /* アライメント用パディング */
} retransmit_event;

enum {
    RETRANS_TYPE_TIMEOUT = 0,
    RETRANS_TYPE_FAST    = 1,
    RETRANS_TYPE_RESET   = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct retransmit_event);
    __uint(max_entries, 1);
} __retransmit_event_map SEC(".maps");

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
