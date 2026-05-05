package bpf

//go:generate sh -c "GOPACKAGE=bpf go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags '-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I ../../bpf/vmlinux -I /usr/include/x86_64-linux-gnu' Retransmit ../../bpf/retransmit.bpf.c -- -I../../bpf"
