//go:build ebpf
// +build ebpf

// Package bpf は eBPF プログラムのロードと Ring Buffer からのイベント受信を担当する。
// このファイルは -tags ebpf を指定した場合のみビルドされる（実機実行時）。
package bpf

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Objects は go generate で生成される RetransmitObjects の alias。
// bpf2go が生成する型名は "<Name>Objects" となる。
type Objects = RetransmitObjects

// Loader は eBPF プログラムのライフサイクルを管理する。
type Loader struct {
	objs   RetransmitObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// NewLoader は eBPF オブジェクトをカーネルにロードし kprobe をアタッチする。
// 呼び出し元は必ず defer loader.Close() を呼ぶこと。
func NewLoader() (*Loader, error) {
	// カーネル 5.11+ では不要だが、古い環境向けに RLIMIT_MEMLOCK を解放する
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	l := &Loader{}

	// go generate で生成された loadRetransmitObjects で eBPF オブジェクトをロード
	if err := loadRetransmitObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	// kprobe: tcp_retransmit_skb
	kp1, err := link.Kprobe("tcp_retransmit_skb", l.objs.HandleTcpRetransmitSkb, nil)
	if err != nil {
		l.objs.Close()
		return nil, fmt.Errorf("kprobe tcp_retransmit_skb: %w", err)
	}
	l.links = append(l.links, kp1)

	// kprobe: tcp_fastretrans_alert
	kp2, err := link.Kprobe("tcp_fastretrans_alert", l.objs.HandleTcpFastretransAlert, nil)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return nil, fmt.Errorf("kprobe tcp_fastretrans_alert: %w", err)
	}
	l.links = append(l.links, kp2)

	// kprobe: tcp_receive_reset
	kp3, err := link.Kprobe("tcp_receive_reset", l.objs.HandleTcpReceiveReset, nil)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return nil, fmt.Errorf("kprobe tcp_receive_reset: %w", err)
	}
	l.links = append(l.links, kp3)

	// Ring Buffer リーダーを生成
	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	l.reader = rd

	return l, nil
}

// Run は Ring Buffer を読み続け、イベントを out チャンネルに送信する。
// ctx がキャンセルされると読み取りを停止し、out を close する。
func (l *Loader) Run(ctx context.Context, out chan<- *RetransmitEvent) {
	defer close(out)

	go func() {
		<-ctx.Done()
		// ctx キャンセル時に reader.Read() をアンブロックするためにクローズ
		_ = l.reader.Close()
	}()

	for {
		record, err := l.reader.Read()
		if err != nil {
			// reader が閉じられた（= ctx がキャンセルされた）場合は正常終了
			if ctx.Err() != nil {
				return
			}
			// ringbuf.ErrClosed は reader.Close() 後に返る
			_, _ = fmt.Fprintf(os.Stderr, "ringbuf read error: %v\n", err)
			return
		}

		event, err := ParseEvent(record.RawSample)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "parse event error: %v\n", err)
			continue
		}

		select {
		case out <- event:
		case <-ctx.Done():
			return
		}
	}
}

// Close はすべての kprobe リンクと eBPF オブジェクトを解放する。
func (l *Loader) Close() {
	if l.reader != nil {
		_ = l.reader.Close()
	}
	l.closeLinks()
	l.objs.Close()
}

func (l *Loader) closeLinks() {
	for _, lnk := range l.links {
		_ = lnk.Close()
	}
	l.links = nil
}
