package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/fanpei91/spn/utils"
)

type Handler interface {
	Lookup(host string) (net.IP, time.Time)
	String() string
}

const (
	DefaultDNSOverHTTPSProvider = "rubyfish.cn:443"
)

type HandlerOverHTTPS struct {
	client    *http.Client
	provider  string
	proxy     Proxy
	staticTTL time.Duration
	timeout   time.Duration
}

type Proxy func(*http.Request) (*url.URL, error)

func NewHandlerOverHTTPS(staticTTL time.Duration, provider string, upstreamToLookupProvider string, timeout time.Duration, proxy Proxy, proxyHeader http.Header) *HandlerOverHTTPS {
	handler := &HandlerOverHTTPS{
		staticTTL: staticTTL,
		provider:  provider,
		proxy:     proxy,
		timeout:   timeout,
		client:    utils.HTTPClient(timeout, proxy, proxyHeader, upstreamToLookupProvider),
	}
	return handler
}

func (h *HandlerOverHTTPS) Lookup(host string) (ip net.IP, expriedAt time.Time) {
	provider := fmt.Sprintf("https://rubyfish.cn/dns-query?name=%s&type=A", host)
	req, _ := http.NewRequest(http.MethodGet, provider, nil)
	req.Header.Set("Accept", "application/dns-json")

	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()
	req = req.WithContext(ctx)

	res, err := h.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, time.Now()
	}

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, time.Now()
	}

	rr := &response{}
	json.NewDecoder(bytes.NewBuffer(buf)).Decode(rr)
	if rr.Status != 0 {
		return nil, time.Now()
	}
	if len(rr.Answer) == 0 {
		return nil, time.Now()
	}

	var answer *answer
	for _, a := range rr.Answer {
		if a.Type == typeIPv4 || a.Type == typeIPv6 {
			answer = &a
			break
		}
	}

	if answer != nil {
		ip = net.ParseIP(answer.Data)
		expriedAt = time.Now().Add(time.Duration(answer.TTL) * time.Second)
		if h.staticTTL != 0 {
			expriedAt = time.Now().Add(h.staticTTL)
		}
	}

	return ip, expriedAt
}

func (h *HandlerOverHTTPS) String() string {
	return fmt.Sprintf(
		"HTTPS[upstream:%s, proxy enabled: %v, timeout: %v, ttl: %d]",
		h.provider,
		h.proxy != nil,
		h.timeout,
		h.staticTTL/time.Second,
	)
}

const (
	typeIPv4 = 1
	typeIPv6 = 28
)

type answer struct {
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
	ip   net.IP
}

type response struct {
	Status int      `json:"Status"`
	Answer []answer `json:"Answer"`
}

type answerCache struct {
	ip        net.IP
	expiredAt time.Time
}

type dnsResolver struct {
	waiters  []chan answerCache
	answer   answerCache
	finished bool
}
