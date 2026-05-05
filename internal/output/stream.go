// Package output は CLI へのストリームログ出力とファイル書き出しを担当する。
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/lumberjack.v2"

	"github.com/tcpretrans/tcpretrans/internal/bpf"
)

// Format はログの出力フォーマット種別。
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Filter はイベントのフィルタリング条件。
type Filter struct {
	IP   string
	Port uint16
	PID  uint32
	Comm string
	Type string // "all" / "timeout" / "fast_retrans" / "reset"
}

// Match は e がフィルタ条件を満たすか返す。
func (f *Filter) Match(e *bpf.RetransmitEvent) bool {
	if f.IP != "" {
		srcIP := e.SrcIP().String()
		dstIP := e.DstIP().String()
		if srcIP != f.IP && dstIP != f.IP {
			return false
		}
	}
	if f.Port != 0 && e.Sport != f.Port && e.Dport != f.Port {
		return false
	}
	if f.PID != 0 && e.Pid != f.PID {
		return false
	}
	if f.Comm != "" && !strings.HasPrefix(e.CommString(), f.Comm) {
		return false
	}
	if f.Type != "" && f.Type != "all" && e.RetransType.String() != f.Type {
		return false
	}
	return true
}

// jsonEvent は JSON Lines 出力用の構造体。
type jsonEvent struct {
	Timestamp   string `json:"timestamp"`
	EventType   string `json:"event_type"`
	SrcAddr     string `json:"saddr"`
	SrcPort     uint16 `json:"sport"`
	DstAddr     string `json:"daddr"`
	DstPort     uint16 `json:"dport"`
	PID         uint32 `json:"pid"`
	Comm        string `json:"comm"`
	RetransType string `json:"retrans_type"`
}

// Writer はイベントを標準出力とオプションのファイルに書き出す。
type Writer struct {
	filter  *Filter
	format  Format
	stdout  io.Writer
	fileOut io.WriteCloser // nil の場合はファイル出力なし
}

// WriterConfig は Writer の設定。
type WriterConfig struct {
	Filter      *Filter
	Format      Format
	LogFile     string
	RotateSizeMB int
}

// NewWriter は WriterConfig に基づいた Writer を生成する。
func NewWriter(cfg WriterConfig) (*Writer, error) {
	w := &Writer{
		filter: cfg.Filter,
		format: cfg.Format,
		stdout: os.Stdout,
	}
	if cfg.Format == "" {
		w.format = FormatText
	}

	if cfg.LogFile != "" {
		rotateMB := cfg.RotateSizeMB
		if rotateMB <= 0 {
			rotateMB = 100
		}
		w.fileOut = &lumberjack.Logger{
			Filename: cfg.LogFile,
			MaxSize:  rotateMB, // MB
			Compress: true,
		}
	}

	return w, nil
}

// Write は 1 イベントを出力する。フィルタに合致しない場合は何もしない。
func (w *Writer) Write(e *bpf.RetransmitEvent) {
	if w.filter != nil && !w.filter.Match(e) {
		return
	}

	var line string
	switch w.format {
	case FormatJSON:
		line = w.formatJSON(e)
	default:
		line = w.formatText(e)
	}

	fmt.Fprintln(w.stdout, line)
	if w.fileOut != nil {
		fmt.Fprintln(w.fileOut, line)
	}
}

// Close はファイル出力をフラッシュして閉じる。
func (w *Writer) Close() error {
	if w.fileOut != nil {
		return w.fileOut.Close()
	}
	return nil
}

func (w *Writer) formatText(e *bpf.RetransmitEvent) string {
	ts := time.Unix(0, int64(e.TimestampNs)).UTC().Format(time.RFC3339Nano)
	return fmt.Sprintf("[%s] %-12s src=%-21s dst=%-21s pid=%-6d comm=%-15s type=%s",
		ts,
		e.RetransType.EventLabel(),
		fmt.Sprintf("%s:%d", e.SrcIP(), e.Sport),
		fmt.Sprintf("%s:%d", e.DstIP(), e.Dport),
		e.Pid,
		e.CommString(),
		e.RetransType.String(),
	)
}

func (w *Writer) formatJSON(e *bpf.RetransmitEvent) string {
	ts := time.Unix(0, int64(e.TimestampNs)).UTC().Format(time.RFC3339Nano)
	j := jsonEvent{
		Timestamp:   ts,
		EventType:   e.RetransType.EventLabel(),
		SrcAddr:     e.SrcIP().String(),
		SrcPort:     e.Sport,
		DstAddr:     e.DstIP().String(),
		DstPort:     e.Dport,
		PID:         e.Pid,
		Comm:        e.CommString(),
		RetransType: e.RetransType.String(),
	}
	b, _ := json.Marshal(j)
	return string(b)
}
