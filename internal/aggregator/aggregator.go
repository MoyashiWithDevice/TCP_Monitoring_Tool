// Package aggregator はフロー単位の TCP 再送イベント集計を担当する。
package aggregator

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/tcpretrans/tcpretrans/internal/bpf"
)

// FlowKey は 4-tuple + プロセス名でフローを一意に識別するキー。
type FlowKey struct {
	SrcIP string
	DstIP string
	Sport uint16
	Dport uint16
	Comm  string
}

// FlowStats はフロー単位の再送統計を保持する。
type FlowStats struct {
	mu sync.Mutex

	TotalCount   uint64
	TimeoutCount uint64
	FastRetrans  uint64
	ResetCount   uint64
	LastSeen     time.Time
	Pid          uint32
}

// Increment はイベント種別に応じてカウンタをインクリメントする。
func (s *FlowStats) Increment(t bpf.RetransType, pid uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	atomic.AddUint64(&s.TotalCount, 1)
	switch t {
	case bpf.RetransTypeTimeout:
		atomic.AddUint64(&s.TimeoutCount, 1)
	case bpf.RetransTypeFast:
		atomic.AddUint64(&s.FastRetrans, 1)
	case bpf.RetransTypeReset:
		atomic.AddUint64(&s.ResetCount, 1)
	}
	s.LastSeen = time.Now()
	s.Pid = pid
}

// Snapshot はフロー統計のコピーを返す（スレッドセーフ）。
func (s *FlowStats) Snapshot() FlowStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return FlowStats{
		TotalCount:   atomic.LoadUint64(&s.TotalCount),
		TimeoutCount: atomic.LoadUint64(&s.TimeoutCount),
		FastRetrans:  atomic.LoadUint64(&s.FastRetrans),
		ResetCount:   atomic.LoadUint64(&s.ResetCount),
		LastSeen:     s.LastSeen,
		Pid:          s.Pid,
	}
}

// Aggregator はすべてのフロー統計を管理する。
type Aggregator struct {
	flows sync.Map // map[FlowKey]*FlowStats
}

// New はゼロ値の Aggregator を返す。
func New() *Aggregator {
	return &Aggregator{}
}

// Record はイベントをフロー単位で集計する。
func (a *Aggregator) Record(e *bpf.RetransmitEvent) {
	key := FlowKey{
		SrcIP: e.SrcIP().String(),
		DstIP: e.DstIP().String(),
		Sport: e.Sport,
		Dport: e.Dport,
		Comm:  e.CommString(),
	}

	val, _ := a.flows.LoadOrStore(key, &FlowStats{})
	stats := val.(*FlowStats)
	stats.Increment(e.RetransType, e.Pid)
}

// FlowEntry は snapshot 取得時に使う FlowKey + FlowStats のペア。
type FlowEntry struct {
	Key   FlowKey
	Stats FlowStats
}

// Snapshot は現在の全フロー統計のスナップショットを返す。
func (a *Aggregator) Snapshot() []FlowEntry {
	var entries []FlowEntry
	a.flows.Range(func(k, v any) bool {
		key := k.(FlowKey)
		stats := v.(*FlowStats)
		entries = append(entries, FlowEntry{
			Key:   key,
			Stats: stats.Snapshot(),
		})
		return true
	})
	return entries
}

// TotalEvents は全フローの再送合計を返す。
func (a *Aggregator) TotalEvents() uint64 {
	var total uint64
	a.flows.Range(func(_, v any) bool {
		s := v.(*FlowStats)
		total += atomic.LoadUint64(&s.TotalCount)
		return true
	})
	return total
}

// FlowCount は観測中のフロー数を返す。
func (a *Aggregator) FlowCount() int {
	var n int
	a.flows.Range(func(_, _ any) bool { n++; return true })
	return n
}
