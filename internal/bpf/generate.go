package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86" Retransmit ../../bpf/retransmit.bpf.c -- -I../../bpf
