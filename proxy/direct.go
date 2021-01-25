package proxy

import (
	"context"
	"net"

	"github.com/fanpei91/spn/dialer"
)

type directClient struct{}

var Direct Client = directClient{}

func (d directClient) Dial(ctx context.Context, network string, ipAddr string) (net.Conn, error) {
	dial, err := dialer.New()
	if err != nil {
		return nil, err
	}

	return dial.DialContext(ctx, network, ipAddr)
}

func (d directClient) String() string {
	return "DIRECT"
}
