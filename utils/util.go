package utils

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/fanpei91/spn/dialer"
)

func Exchange(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func HTTPClient(timeout time.Duration, proxy func(*http.Request) (*url.URL, error), proxyHeader http.Header, dns string) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: proxy,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d, err := dialer.NewWithResolver(dns)
				if err != nil {
					return nil, err
				}

				return d.DialContext(ctx, network, addr)
			},
			ProxyConnectHeader: proxyHeader,
		},
	}
}
