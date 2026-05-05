// tcpretrans は eBPF を用いて TCP 再送イベントをリアルタイムに可視化するツール。
//
// 使用例:
//
//	sudo ./tcpretrans
//	sudo ./tcpretrans --filter-port 443 --log-file /var/log/tcp_retrans.log
//	sudo ./tcpretrans --log-format json --no-metrics
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/tcpretrans/tcpretrans/internal/aggregator"
	"github.com/tcpretrans/tcpretrans/internal/bpf"
	"github.com/tcpretrans/tcpretrans/internal/metrics"
	"github.com/tcpretrans/tcpretrans/internal/output"
)

// Version はビルド時に -ldflags で注入する。
var Version = "dev"

type config struct {
	filterIP     string
	filterPort   uint16
	filterPID    uint32
	filterComm   string
	filterType   string
	logFile      string
	logFormat    string
	logRotateMB  int
	metricsPort  uint16
	maxFlows     uint
	noMetrics    bool
	verbose      bool
}

func main() {
	cfg := &config{}

	root := &cobra.Command{
		Use:   "tcpretrans",
		Short: "Visualize TCP retransmission events via eBPF",
		Long: `tcpretrans attaches kprobes to the Linux TCP stack and streams
retransmission events in real time. Requires root or CAP_BPF + CAP_PERFMON.`,
		Version:      Version,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cfg)
		},
	}

	f := root.Flags()
	f.StringVar(&cfg.filterIP,    "filter-ip",          "",       "Filter by IP address (src or dst)")
	f.Uint16Var(&cfg.filterPort,  "filter-port",         0,        "Filter by port number (src or dst)")
	f.Uint32Var(&cfg.filterPID,   "filter-pid",          0,        "Filter by PID")
	f.StringVar(&cfg.filterComm,  "filter-comm",         "",       "Filter by process name (prefix match)")
	f.StringVar(&cfg.filterType,  "type",                "all",    "Retransmit type: all|timeout|fast_retrans|reset")
	f.StringVar(&cfg.logFile,     "log-file",            "",       "File path for event log output")
	f.StringVar(&cfg.logFormat,   "log-format",          "text",   "Log format: text|json")
	f.IntVar(&cfg.logRotateMB,    "log-rotate-size",     100,      "Log rotate size limit (MB)")
	f.Uint16Var(&cfg.metricsPort, "metrics-port",        9101,     "Prometheus metrics port")
	f.UintVar(&cfg.maxFlows,      "metrics-max-flows",   10000,    "Max number of flow label sets")
	f.BoolVar(&cfg.noMetrics,     "no-metrics",          false,    "Disable Prometheus exporter")
	f.BoolVar(&cfg.verbose,       "verbose",             false,    "Enable debug logging")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cfg *config) error {
	// ロガー初期化
	var logger *zap.Logger
	var err error
	if cfg.verbose {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("tcpretrans starting", zap.String("version", Version))

	// eBPF ローダー起動
	loader, err := bpf.NewLoader()
	if err != nil {
		return fmt.Errorf("load eBPF: %w", err)
	}
	defer loader.Close()
	logger.Info("eBPF programs loaded and kprobes attached")

	// フィルタ設定
	filter := &output.Filter{
		IP:   cfg.filterIP,
		Port: cfg.filterPort,
		PID:  cfg.filterPID,
		Comm: cfg.filterComm,
		Type: cfg.filterType,
	}

	// Writer 初期化
	writer, err := output.NewWriter(output.WriterConfig{
		Filter:       filter,
		Format:       output.Format(cfg.logFormat),
		LogFile:      cfg.logFile,
		RotateSizeMB: cfg.logRotateMB,
	})
	if err != nil {
		return fmt.Errorf("init writer: %w", err)
	}
	defer writer.Close()

	// Aggregator 初期化
	agg := aggregator.New()

	// Prometheus エクスポーター起動
	var exp *metrics.Exporter
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if !cfg.noMetrics {
		exp = metrics.NewExporter()
		go func() {
			logger.Info("metrics server starting", zap.Uint16("port", cfg.metricsPort))
			if err := exp.StartServer(ctx, cfg.metricsPort); err != nil {
				logger.Error("metrics server error", zap.Error(err))
			}
		}()

		// 定期的に Aggregator のスナップショットで Prometheus を更新
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					exp.Update(agg.Snapshot())
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// シグナルハンドリング
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	// イベントループ
	eventCh := make(chan *bpf.RetransmitEvent, 4096)
	go loader.Run(ctx, eventCh)

	logger.Info("listening for TCP retransmit events... (Ctrl+C to stop)")

	for e := range eventCh {
		agg.Record(e)
		writer.Write(e)

		if cfg.verbose {
			logger.Debug("event",
				zap.String("src", fmt.Sprintf("%s:%d", e.SrcIP(), e.Sport)),
				zap.String("dst", fmt.Sprintf("%s:%d", e.DstIP(), e.Dport)),
				zap.String("type", e.RetransType.String()),
				zap.Uint32("pid", e.Pid),
				zap.String("comm", e.CommString()),
			)
		}
	}

	logger.Info("tcpretrans stopped",
		zap.Uint64("total_events", agg.TotalEvents()),
		zap.Int("flows_observed", agg.FlowCount()),
	)
	return nil
}
