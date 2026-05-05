package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
//   -cc clang \
//   -cflags "-O2 -g -Wall -I../../bpf/vmlinux" \
//   Retransmit ../../bpf/retransmit.bpf.c