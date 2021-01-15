package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/fanpei91/spn/dialer"
	"github.com/miekg/dns"
)

type Handler interface {
	Lookup(r *dns.Msg) (*dns.Msg, error)
	String() string
}

const (
	DefaultDNSOverHTTPSProvider = "rubyfish.cn:443"
)

type HandlerOverHTTPS struct {
	client   *http.Client
	provider string
	proxy    Proxy
	ttl      uint32
	timeout  time.Duration
}

type Proxy func(*http.Request) (*url.URL, error)

func NewHandlerOverHTTPS(ttl uint32, provider string, upstreamToLookupProvider string, timeout time.Duration, proxy Proxy, proxyHeader http.Header) *HandlerOverHTTPS {
	hander := &HandlerOverHTTPS{
		ttl:      ttl,
		provider: provider,
		proxy:    proxy,
		timeout:  timeout,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy: proxy,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					d, err := dialer.NewWithResolver(upstreamToLookupProvider)
					if err != nil {
						return nil, err
					}

					return d.DialContext(ctx, network, addr)
				},
				ProxyConnectHeader: proxyHeader,
			},
		},
	}
	return hander
}

func (h *HandlerOverHTTPS) Lookup(question *dns.Msg) (*dns.Msg, error) {
	packed, _ := question.Pack()
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/dns-query", h.provider), bytes.NewBuffer(packed))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	res, err := h.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("provider failure with status code: %d", res.StatusCode))
	}

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, res.Body); err != nil {
		return nil, err
	}

	answer := new(dns.Msg)

	if err := answer.Unpack(buf.Bytes()); err != nil {
		return nil, err
	}

	modifyTTL(answer, h.ttl)
	return answer, nil
}

func (h *HandlerOverHTTPS) String() string {
	return fmt.Sprintf("HTTPS[upstream:%s, proxy enabled: %v, timeout: %v, ttl: %d]", h.provider, h.proxy != nil, h.timeout, h.ttl)
}
