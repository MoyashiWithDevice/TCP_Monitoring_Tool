package bpf

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

// RetransmitObjects は eBPF オブジェクトのマップとプログラムを保持する。
type RetransmitObjects struct {
	Events                    *ebpf.Map     `ebpf:"events"`
	HandleTcpRetransmitSkb    *ebpf.Program `ebpf:"kprobe/tcp_retransmit_skb"`
	HandleTcpFastretransAlert *ebpf.Program `ebpf:"kprobe/tcp_fastretrans_alert"`
	HandleTcpReceiveReset     *ebpf.Program `ebpf:"kprobe/tcp_receive_reset"`
}

// Close はオブジェクト内のリソースを解放する。
func (o *RetransmitObjects) Close() error {
	var firstErr error
	closeIf := func(c interface{ Close() error }) {
		if c == nil {
			return
		}
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	closeIf(o.Events)
	closeIf(o.HandleTcpRetransmitSkb)
	closeIf(o.HandleTcpFastretransAlert)
	closeIf(o.HandleTcpReceiveReset)

	return firstErr
}

// loadRetransmitObjects は bpf/retransmit.bpf.o を読み込み、オブジェクトを初期化する。
func loadRetransmitObjects(objs *RetransmitObjects, opts *ebpf.CollectionOptions) error {
	objPath, err := resolveBPFObjectPath()
	if err != nil {
		return err
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	if opts == nil {
		opts = &ebpf.CollectionOptions{}
	}

	if err := spec.LoadAndAssign(objs, opts); err != nil {
		return fmt.Errorf("load and assign eBPF objects: %w", err)
	}

	return nil
}

func resolveBPFObjectPath() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}

	objPath := filepath.Join(wd, "bpf", "retransmit.bpf.o")
	if _, err := os.Stat(objPath); err == nil {
		return objPath, nil
	}

	return "", fmt.Errorf("bpf object file not found: %s", objPath)
}
