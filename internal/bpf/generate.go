package bpf

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -I../../bpf/vmlinux" Retransmit ../../bpf/retransmit.bpf.c