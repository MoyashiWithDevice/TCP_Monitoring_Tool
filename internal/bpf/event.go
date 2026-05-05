// Package bpf は eBPF プログラムのロードと Ring Buffer からのイベント受信を担当する。
package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// RetransType は TCP 再送の種別を表す。
type RetransType uint8

const (
	RetransTypeTimeout RetransType = 0
	RetransTypeFast    RetransType = 1
	RetransTypeReset   RetransType = 2
)

// String は RetransType を人が読める文字列に変換する。
func (t RetransType) String() string {
	switch t {
	case RetransTypeTimeout:
		return "timeout"
	case RetransTypeFast:
		return "fast_retrans"
	case RetransTypeReset:
		return "reset"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// EventLabel は Prometheus のイベント種別ラベル文字列を返す。
func (t RetransType) EventLabel() string {
	switch t {
	case RetransTypeTimeout:
		return "RETRANS"
	case RetransTypeFast:
		return "FAST_RETRANS"
	case RetransTypeReset:
		return "RESET"
	default:
		return "UNKNOWN"
	}
}

// RetransmitEvent は eBPF Ring Buffer から受信する 1 イベント分のデータ。
// C 側の struct retransmit_event と必ずバイトレイアウトが一致すること。
//
// オフセット計算:
//
//	0  : TimestampNs (8 bytes)
//	8  : Pid        (4 bytes)
//	12 : Comm       (16 bytes)
//	28 : Saddr      (4 bytes)
//	32 : Daddr      (4 bytes)
//	36 : Sport      (2 bytes)
//	38 : Dport      (2 bytes)
//	40 : RetransType (1 byte)
//	41 : Pad        (3 bytes)
//	合計: 44 bytes
type RetransmitEvent struct {
	TimestampNs uint64
	Pid         uint32
	Comm        [16]byte
	Saddr       uint32
	Daddr       uint32
	Sport       uint16
	Dport       uint16
	RetransType RetransType
	Pad         [3]byte
}

// EventSize は RetransmitEvent の固定バイトサイズ。
const EventSize = 44

// ParseEvent は Ring Buffer から受け取った生バイト列を RetransmitEvent にパースする。
// バイトオーダーはリトルエンディアン（x86_64 前提）。
func ParseEvent(raw []byte) (*RetransmitEvent, error) {
	if len(raw) < EventSize {
		return nil, fmt.Errorf("event too short: got %d bytes, want %d", len(raw), EventSize)
	}

	e := &RetransmitEvent{}
	bo := binary.LittleEndian

	e.TimestampNs = bo.Uint64(raw[0:8])
	e.Pid = bo.Uint32(raw[8:12])
	copy(e.Comm[:], raw[12:28])
	e.Saddr = bo.Uint32(raw[28:32])
	e.Daddr = bo.Uint32(raw[32:36])
	e.Sport = bo.Uint16(raw[36:38])
	e.Dport = binary.BigEndian.Uint16(raw[38:40]) // dport はネットワークバイトオーダー
	e.RetransType = RetransType(raw[40])

	return e, nil
}

// CommString は NULL 終端のコマンド名を Go の string に変換する。
func (e *RetransmitEvent) CommString() string {
	n := strings.IndexByte(string(e.Comm[:]), 0)
	if n < 0 {
		n = len(e.Comm)
	}
	return string(e.Comm[:n])
}

// SrcIP は送信元 IP アドレスを net.IP 形式で返す。
func (e *RetransmitEvent) SrcIP() net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, e.Saddr)
	return ip
}

// DstIP は宛先 IP アドレスを net.IP 形式で返す。
func (e *RetransmitEvent) DstIP() net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, e.Daddr)
	return ip
}
