// Package metrics は Prometheus メトリクスの管理と HTTP エクスポートを担当する。
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tcpretrans/tcpretrans/internal/aggregator"
	"github.com/tcpretrans/tcpretrans/internal/bpf"
)

// flowLabels はフロー単位のラベルキー。
var flowLabels = []string{"src_ip", "src_port", "dst_ip", "dst_port", "comm"}

// Exporter は Prometheus メトリクスの登録と更新を管理する。
type Exporter struct {
	retransTotal     *prometheus.CounterVec
	retransByType    *prometheus.CounterVec
	activeFlows      prometheus.Gauge
	lastSeenSeconds  *prometheus.GaugeVec

	// カウンタはリセット不可なので、前回値を保持して差分だけ Add する
	// ここではシンプルに labelValues → 最終カウント のマップで管理
	prevTotal   map[string]uint64
	prevTimeout map[string]uint64
	prevFast    map[string]uint64
	prevReset   map[string]uint64

	reg *prometheus.Registry
}

// NewExporter は新しい Exporter を生成し、メトリクスを登録する。
func NewExporter() *Exporter {
	reg := prometheus.NewRegistry()

	e := &Exporter{
		retransTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tcp_retransmit_total",
			Help: "Total number of TCP retransmissions per flow.",
		}, flowLabels),

		retransByType: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tcp_retransmit_by_type_total",
			Help: "TCP retransmissions by type per flow.",
		}, append(flowLabels, "type")),

		activeFlows: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tcp_retransmit_active_flows",
			Help: "Number of currently observed flows with retransmissions.",
		}),

		lastSeenSeconds: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tcp_retransmit_last_seen_seconds",
			Help: "Unix timestamp of the last retransmission event per flow.",
		}, flowLabels),

		prevTotal:   make(map[string]uint64),
		prevTimeout: make(map[string]uint64),
		prevFast:    make(map[string]uint64),
		prevReset:   make(map[string]uint64),

		reg: reg,
	}

	reg.MustRegister(e.retransTotal)
	reg.MustRegister(e.retransByType)
	reg.MustRegister(e.activeFlows)
	reg.MustRegister(e.lastSeenSeconds)

	return e
}

// Update は Aggregator のスナップショットからメトリクスを更新する。
func (e *Exporter) Update(entries []aggregator.FlowEntry) {
	e.activeFlows.Set(float64(len(entries)))

	for _, entry := range entries {
		k := entry.Key
		s := entry.Stats

		sport := fmt.Sprintf("%d", k.Sport)
		dport := fmt.Sprintf("%d", k.Dport)
		lvs := prometheus.Labels{
			"src_ip":   k.SrcIP,
			"src_port": sport,
			"dst_ip":   k.DstIP,
			"dst_port": dport,
			"comm":     k.Comm,
		}

		mapKey := fmt.Sprintf("%s:%s->%s:%s(%s)", k.SrcIP, sport, k.DstIP, dport, k.Comm)

		// total カウンタ: 前回との差分を Add
		if diff := s.TotalCount - e.prevTotal[mapKey]; diff > 0 {
			e.retransTotal.With(lvs).Add(float64(diff))
			e.prevTotal[mapKey] = s.TotalCount
		}

		// type 別カウンタ
		typeMap := map[string]struct {
			cur  uint64
			prev *map[string]uint64
		}{
			bpf.RetransTypeTimeout.String(): {s.TimeoutCount, &e.prevTimeout},
			bpf.RetransTypeFast.String():    {s.FastRetrans, &e.prevFast},
			bpf.RetransTypeReset.String():   {s.ResetCount, &e.prevReset},
		}
		for typeName, data := range typeMap {
			prev := (*data.prev)[mapKey]
			if diff := data.cur - prev; diff > 0 {
				lvsWithType := prometheus.Labels{
					"src_ip":   k.SrcIP,
					"src_port": sport,
					"dst_ip":   k.DstIP,
					"dst_port": dport,
					"comm":     k.Comm,
					"type":     typeName,
				}
				e.retransByType.With(lvsWithType).Add(float64(diff))
				(*data.prev)[mapKey] = data.cur
			}
		}

		// last_seen ゲージ
		e.lastSeenSeconds.With(lvs).Set(float64(s.LastSeen.UnixNano()) / 1e9)
	}
}

// ServeHTTP は /metrics エンドポイントを提供する HTTP ハンドラを返す。
func (e *Exporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.reg, promhttp.HandlerOpts{})
}

// StartServer は指定ポートで Prometheus HTTP サーバを起動する。
// ctx がキャンセルされるとサーバをシャットダウンする。
func (e *Exporter) StartServer(ctx context.Context, port uint16) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", e.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("metrics server: %w", err)
	}
	return nil
}
