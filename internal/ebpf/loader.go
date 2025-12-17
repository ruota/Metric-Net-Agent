package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86" NetAgent ../../bpf/net.bpf.c -- -I../../bpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type Loader struct {
	Objects        NetAgentObjects
	LinkTCPConnect link.Link
	LinkTCPSend    link.Link
	LinkTCPRecv    link.Link
	LinkUDPSend    link.Link
	LinkUDPRecv    link.Link
}

func (l *Loader) LoadAndAttach() error {
	if err := LoadNetAgentObjects(&l.Objects, nil); err != nil {
		return fmt.Errorf("load objects: %w", err)
	}
	var err error
	if l.LinkTCPConnect, err = link.Kprobe("tcp_v4_connect", l.Objects.OnTcpV4Connect, nil); err != nil {
		return fmt.Errorf("attach kprobe tcp_v4_connect: %w", err)
	}
	if l.LinkTCPSend, err = link.Kprobe("tcp_sendmsg", l.Objects.OnTcpSendmsg, nil); err != nil {
		return fmt.Errorf("attach kprobe tcp_sendmsg: %w", err)
	}
	if l.LinkTCPRecv, err = link.Kprobe("tcp_recvmsg", l.Objects.OnTcpRecvmsg, nil); err != nil {
		return fmt.Errorf("attach kprobe tcp_recvmsg: %w", err)
	}
	if l.LinkUDPSend, err = link.Kprobe("udp_sendmsg", l.Objects.OnUdpSendmsg, nil); err != nil {
		return fmt.Errorf("attach kprobe udp_sendmsg: %w", err)
	}
	if l.LinkUDPRecv, err = link.Kprobe("udp_recvmsg", l.Objects.OnUdpRecvmsg, nil); err != nil {
		return fmt.Errorf("attach kprobe udp_recvmsg: %w", err)
	}
	return nil
}

func (l *Loader) Close() {
	for _, lk := range []link.Link{l.LinkTCPConnect, l.LinkTCPSend, l.LinkTCPRecv, l.LinkUDPSend, l.LinkUDPRecv} {
		if lk != nil {
			_ = lk.Close()
		}
	}
	l.Objects.Close()
}
