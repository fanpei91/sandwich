package tun

import (
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// The all following code is from https://github.com/xjasonlyu/tun2socks
type endpoint struct {
	mtu uint32
	rwc io.ReadWriteCloser
	wg  sync.WaitGroup

	dispatcher         stack.NetworkDispatcher
	LinkEPCapabilities stack.LinkEndpointCapabilities
}

func newEndpoint(rwc io.ReadWriteCloser, mtu uint32) *endpoint {
	return &endpoint{
		rwc: rwc,
		mtu: mtu,
	}
}

func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	go e.dispatchLoop()
	e.dispatcher = dispatcher
}

func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *endpoint) WritePacket(_ *stack.Route, _ *stack.GSO, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	return e.writePacket(pkt)
}

func (e *endpoint) WritePackets(_ *stack.Route, _ *stack.GSO, pkts stack.PacketBufferList, _ tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	n := 0
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if err := e.writePacket(pkt); err != nil {
			break
		}
		n++
	}
	return n, nil
}

func (e *endpoint) MTU() uint32 {
	return e.mtu
}

func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.LinkEPCapabilities
}

func (*endpoint) MaxHeaderLength() uint16 {
	return 0
}

func (*endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (*endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *endpoint) AddHeader(tcpip.LinkAddress, tcpip.LinkAddress, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func (e *endpoint) Wait() {
	e.wg.Wait()
}

func (e *endpoint) Close() error {
	return e.rwc.Close()
}

func (e *endpoint) dispatchLoop() {
	e.wg.Add(1)
	defer e.wg.Done()

	for {
		packet := make([]byte, e.mtu)
		n, err := e.rwc.Read(packet)
		if err != nil {
			break
		}

		if !e.IsAttached() {
			continue
		}

		var p tcpip.NetworkProtocolNumber
		switch header.IPVersion(packet) {
		case header.IPv4Version:
			p = header.IPv4ProtocolNumber
		case header.IPv6Version:
			p = header.IPv6ProtocolNumber
		}

		e.dispatcher.DeliverNetworkPacket("", "", p, &stack.PacketBuffer{
			Data: buffer.View(packet[:n]).ToVectorisedView(),
		})
	}
}

func (e *endpoint) writePacket(pkt *stack.PacketBuffer) *tcpip.Error {
	networkHdr := pkt.NetworkHeader().View()
	transportHdr := pkt.TransportHeader().View()
	payload := pkt.Data.ToView()

	buf := buffer.NewVectorisedView(
		len(networkHdr)+len(transportHdr)+len(payload),
		[]buffer.View{networkHdr, transportHdr, payload},
	)

	if _, err := e.rwc.Write(buf.ToView()); err != nil {
		return tcpip.ErrInvalidEndpointState
	}

	return nil
}
