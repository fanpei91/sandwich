package dns

import (
	"fmt"
	"time"

	"github.com/fanpei91/spn/dialer"
	"github.com/miekg/dns"
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

func (h *HandlerOverUDP) Lookup(question *dns.Msg) (*dns.Msg, error) {
	client := new(dns.Client)
	d, err := dialer.New()
	if err != nil {
		return nil, err
	}

	d.Timeout = h.timeout
	client.Dialer = d
	answer, _, err := client.Exchange(question, h.upstream)
	if err != nil {
		return nil, err
	}

	modifyTTL(answer, 0)
	return answer, nil
}

func (h *HandlerOverUDP) String() string {
	return fmt.Sprintf("UDP[upstream: %v, timeout: %v]", h.upstream, h.timeout)
}
