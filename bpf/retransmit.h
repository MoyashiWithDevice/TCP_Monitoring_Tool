/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RETRANSMIT_H
#define __RETRANSMIT_H

/* 再送種別 */
#define RETRANS_TYPE_TIMEOUT     0
#define RETRANS_TYPE_FAST        1
#define RETRANS_TYPE_RESET       2

/* カーネル → ユーザーランド 転送イベント構造体
 * Go 側の RetransmitEvent と必ずレイアウトを一致させること。
 * __attribute__((packed)) は使わず、手動でパディングを入れる。
 */
struct retransmit_event {
    __u64 timestamp_ns;   /* bpf_ktime_get_ns() */
    __u32 pid;            /* tgid (ユーザーから見た PID) */
    __u8  comm[16];       /* プロセス名 (最大 15 文字 + NUL) */
    __u32 saddr;          /* 送信元 IPv4 アドレス (ネットワークバイトオーダー) */
    __u32 daddr;          /* 宛先   IPv4 アドレス (ネットワークバイトオーダー) */
    __u16 sport;          /* 送信元ポート (ホストバイトオーダー) */
    __u16 dport;          /* 宛先   ポート (ネットワークバイトオーダー → 読み取り時に変換) */
    __u8  retrans_type;   /* RETRANS_TYPE_* */
    __u8  pad[3];         /* アライメント用パディング */
};

#endif /* __RETRANSMIT_H */
