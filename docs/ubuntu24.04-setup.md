# Ubuntu 24.04 へのデプロイセットアップ手順

## 1. 前提条件

- Ubuntu 24.04
- x86_64 カーネル
- root 権限（eBPF のロード / `bpftool` の実行のため）
- `clang 14+`, `go 1.22+`, `bpftool`
- `linux-headers-$(uname -r)` またはカーネルの BTF 有効化

---

## 2. 必要パッケージのインストール

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  clang \
  llvm \
  libelf-dev \
  linux-headers-$(uname -r) \
  bpftool \
  git \
  ca-certificates \
  make
```

### Go のインストール

Ubuntu 24.04 に `go1.22` が入手可能であれば:

```bash
sudo apt install -y golang-go
```

apt 版が古い場合は、公式の Go バイナリをダウンロードしてインストールしてください。

---

## 3. リポジトリの取得

```bash
cd /opt
git clone https://github.com/MoyashiWithDevice/TCP_Monitoring_Tool.git
cd TCP_Monitoring_Tool
```

---

## 4. ビルド前の確認

```bash
go version
clang --version
bpftool version
uname -r
```

`go version` が `go1.22` 以上であることを確認してください。

---

## 5. `vmlinux.h` の生成

`Makefile` にある通り、`bpftool` でカーネル BTF を取得します。

```bash
sudo make vmlinux
```

成功すると `bpf/vmlinux/vmlinux.h` が生成されます。

> `sudo` 必須: `/sys/kernel/btf/vmlinux` へアクセスするために root 権限が必要です。

---

## 6. eBPF と Go バイナリのビルド

```bash
make all
```

`make all` は以下を実行します。

- `vmlinux.h` の存在確認
- `bpf/retransmit.bpf.c` の eBPF コンパイル
- `go generate ./internal/bpf/...`
- `go build ./cmd/tcpretrans/`

---

## 7. 実行

ビルド成功後、生成バイナリは `bin/tcpretrans` にあります。

```bash
sudo ./bin/tcpretrans
```

eBPF のロードには root 権限が必要です。

---

## 8. テスト・Lint（任意）

### ユニットテスト実行

```bash
make test
```

### Lint 実行

`golangci-lint` を使う場合:

```bash
sudo apt install -y golangci-lint
make lint
```

---

## 9. トラブルシューティング

- `vmlinux.h not found` の場合:
  - `sudo make vmlinux` を実行
  - カーネルが BTF 非対応の場合は `linux-headers` またはカーネル構成を確認

- `clang` で BPF コンパイルエラーが出る場合:
  - `clang` が `-target bpf` をサポートしていること
  - `linux-headers` が正しくインストールされていること

---

## 10. まとめ

1. Ubuntu 24.04 を更新
2. `clang`, `go`, `bpftool`, `linux-headers` をインストール
3. リポジトリをクローン
4. `sudo make vmlinux`
5. `make all`
6. `sudo ./bin/tcpretrans`

これで Ubuntu 24.04 上で `TCP_Monitoring_Tool` のセットアップと実行ができます。
