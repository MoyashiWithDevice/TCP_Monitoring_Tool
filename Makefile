# tcpretrans Makefile
# 前提: clang 14+, go 1.22+, bpftool, linux-headers (または BTF が有効なカーネル)

BINARY     := bin/tcpretrans
MODULE     := github.com/tcpretrans/tcpretrans
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -ldflags "-X main.Version=$(VERSION)"

BPF_SRC    := bpf/retransmit.bpf.c
BPF_OBJ    := bpf/retransmit.bpf.o
VMLINUX_H  := bpf/vmlinux/vmlinux.h

CLANG      := clang
CLANG_FLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
               -I bpf/vmlinux \
               -I /usr/include/$(shell uname -m)-linux-gnu

.PHONY: all generate build test lint clean vmlinux

## all: vmlinux.h 生成 → eBPF コンパイル → Go バイナリビルド
all: generate build

## vmlinux: bpftool で vmlinux.h を生成する (要 root / /sys/kernel/btf/vmlinux)
vmlinux:
	@echo "[vmlinux] Generating vmlinux.h via bpftool..."
	@mkdir -p bpf/vmlinux
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)
	@echo "[vmlinux] Done: $(VMLINUX_H)"

## generate: eBPF C をコンパイルし、bpf2go で Go スタブを生成する
generate: $(VMLINUX_H)
	@echo "[generate] Running bpf2go..."
	cd internal/bpf && go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I ../../bpf/vmlinux -I /usr/include/x86_64-linux-gnu" Retransmit ../../bpf/retransmit.bpf.c -- -I../../bpf
	@echo "[generate] Done"

## build: Go バイナリをビルドする
build:
	@echo "[build] Building $(BINARY)..."
	CGO_ENABLED=0 go build -tags ebpf $(LDFLAGS) -o $(BINARY) ./cmd/tcpretrans/
	@echo "[build] Done: $(BINARY)"

## test: ユニットテストを実行する (eBPF ロードを要しないテストのみ)
test:
	@echo "[test] Running unit tests..."
	go test -v -count=1 \
		./internal/bpf/... \
		./internal/aggregator/... \
		./internal/output/...
	@echo "[test] Done"

## lint: golangci-lint を実行する
lint:
	@command -v golangci-lint >/dev/null 2>&1 || \
		(echo "golangci-lint not found. Install: https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

## clean: 生成ファイルとバイナリを削除する
clean:
	@echo "[clean] Removing generated files and binary..."
	rm -f $(BPF_OBJ) $(BINARY)
	rm -f internal/bpf/retransmit_bpf*.go internal/bpf/retransmit_bpf*.o
	@echo "[clean] Done"

# vmlinux.h がなければ vmlinux ターゲットを実行する
$(VMLINUX_H):
	@echo "[info] vmlinux.h not found. Run 'make vmlinux' first (requires root and /sys/kernel/btf/vmlinux)"
	@exit 1
