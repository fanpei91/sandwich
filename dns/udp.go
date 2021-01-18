package dns

import (
	"context"
	"fmt"
	"github.com/fanpei91/spn/dialer"
	"net"
	"time"
)

type HandlerOverUDP struct {
	upstream string
	timeout  time.Duration
}

func NewHandlerOverUDP(upstream string, timeout time.Duration) *HandlerOverUDP {
	return &HandlerOverUDP{
		upstream: upstream,
		timeout:  timeout,
	}
}

func (h *HandlerOverUDP) Lookup(ctx context.Context, host string) (ip net.IP, expriedAt time.Time) {
	resolver := new(net.Resolver)
	resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		d, err := dialer.New()
		if err != nil {
			return nil, err
		}
		return d.DialContext(ctx, "udp", h.upstream)
	}

	ips, err := resolver.LookupIP(ctx, "ip", host)
	expriedAt = time.Now()
	if err != nil {
		return nil, expriedAt
	}

	return ips[0], expriedAt
}

func (h *HandlerOverUDP) String() string {
	return fmt.Sprintf("UDP[upstream: %v, timeout: %v]", h.upstream, h.timeout)
}
