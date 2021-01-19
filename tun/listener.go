package tun

import (
	"errors"
	"net"
	"time"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/fanpei91/spn/dialer"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Listener struct {
	stack  *stack.Stack
	tcpCh  chan net.Conn
	udpCh  chan net.Conn
	closed bool
	ep     *endpoint
	iface  string
}

func Listen(mtu int) (*Listener, error) {
	device, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, err
	}

	if mtu, err = device.MTU(); err != nil {
		return nil, err
	}

	s := stack.New(
		stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
			},
		},
	)

	ep := newEndpoint(&unixTun{device: device}, uint32(mtu))
	l := &Listener{
		stack: s,
		tcpCh: make(chan net.Conn, 1),
		udpCh: make(chan net.Conn, 1),
		ep:    ep,
	}
	l.iface, _ = device.Name()

	s.SetForwarding(ipv4.ProtocolNumber, true)
	s.SetForwarding(ipv6.ProtocolNumber, true)

	l.setTCPHandler()
	l.setUDPHandler()

	withTCPSACK(s)
	withDefaultTTL(s)
	withTCPBufferSizeRange(s)
	withTCPCongestionControl(s)
	withTCPModerateReceiveBuffer(s)

	s.CreateNIC(1, ep)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         1,
		},
	})
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)

	return l, nil
}

func (l *Listener) Iface() string {
	return l.iface
}

func (l *Listener) AcceptTCP() net.Conn {
	return <-l.tcpCh
}

func (l *Listener) AcceptUDP() net.Conn {
	return <-l.udpCh
}

func (l *Listener) setTCPHandler() {
	forwarder := tcp.NewForwarder(l.stack, 2<<10, 2<<10, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		id := r.ID()
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}

		setKeepalive(ep)

		r.Complete(false)
		l.tcpCh <- newTunConn(id, gonet.NewTCPConn(&wq, ep))
	})

	l.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
}

func setKeepalive(ep tcpip.Endpoint) {
	const interval = 30 * time.Second
	const count = 10
	{
		opt := tcpip.KeepaliveIdleOption(interval)
		ep.SetSockOpt(&opt)
	}

	{
		opt := tcpip.KeepaliveIntervalOption(interval)
		ep.SetSockOpt(&opt)
	}

	{
		opt := tcpip.TCPUserTimeoutOption(interval * (count + 1))
		ep.SetSockOpt(&opt)
	}

	ep.SetSockOptInt(tcpip.KeepaliveCountOption, count)
}

func (l *Listener) setUDPHandler() {
	forwarder := udp.NewForwarder(l.stack, func(r *udp.ForwarderRequest) {
		var wq waiter.Queue
		id := r.ID()
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}

		l.udpCh <- newTunConn(id, gonet.NewUDPConn(l.stack, &wq, ep))
	})

	l.stack.SetTransportProtocolHandler(udp.ProtocolNumber, forwarder.HandlePacket)
}

func (l *Listener) Close() error {
	if l.closed {
		return errors.New("use of closed network connection")
	}

	l.closed = true

	l.stack.Close()
	l.ep.Close()

	close(l.udpCh)
	close(l.tcpCh)

	return nil
}

func newTunConn(id stack.TransportEndpointID, conn net.Conn) dialer.Conn {
	return dialer.Conn{
		Conn: conn,
		Local: dialer.Addr{
			IP:   net.ParseIP(id.RemoteAddress.String()),
			Port: int(id.RemotePort),
			Net:  conn.RemoteAddr().Network(),
		},
		Remote: dialer.Addr{
			IP:   net.ParseIP(id.LocalAddress.String()),
			Port: int(id.LocalPort),
			Net:  conn.LocalAddr().Network(),
		},
	}
}

// From https://github.com/xjasonlyu/tun2socks
const (
	offset = 4
)

func withTCPSACK(s *stack.Stack) {
	v := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &v)
}

func withDefaultTTL(s *stack.Stack) {
	opt := tcpip.DefaultTTLOption(64)
	s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt)
	s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &opt)
}

func withTCPBufferSizeRange(s *stack.Stack) {
	const bufferSize = 32 * 1024 * 1024

	{
		opt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 1, Default: bufferSize, Max: bufferSize}
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
	}

	{
		opt := tcpip.TCPSendBufferSizeRangeOption{Min: 1, Default: bufferSize, Max: bufferSize}
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
	}
}

func withTCPCongestionControl(s *stack.Stack) {
	opt := tcpip.CongestionControlOption("cubic")
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
}

func withTCPModerateReceiveBuffer(s *stack.Stack) {
	opt := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
}

type unixTun struct {
	device tun.Device
}

func (t *unixTun) Read(packet []byte) (n int, err error) {
	buf := pool.Get(offset + len(packet))
	defer pool.Put(buf)

	if n, err = t.device.Read(buf, offset); err != nil {
		return
	}

	copy(packet, buf[offset:offset+n])
	return
}

func (t *unixTun) Write(packet []byte) (int, error) {
	buf := pool.Get(offset + len(packet))
	defer pool.Put(buf)

	copy(buf[offset:], packet)
	return t.device.Write(buf[:offset+len(packet)], offset)
}

func (t *unixTun) Close() error {
	return t.device.Close()
}
