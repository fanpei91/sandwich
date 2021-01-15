package dialer

import (
	"context"
	"net"
)

var hook = func(dialer *net.Dialer) error {
	return nil
}

func New() (*net.Dialer, error) {
	dialer := new(net.Dialer)
	if err := hook(dialer); err != nil {
		return nil, err
	}
	return dialer, nil
}

func NewWithResolver(dns string) (*net.Dialer, error) {
	d, err := New()
	if err != nil {
		return nil, err
	}

	d.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d, err := New()
			if err != nil {
				return nil, err
			}
			return d.DialContext(ctx, network, dns)
		},
	}

	return d, nil
}
