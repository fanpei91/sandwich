package dns

import (
	"errors"
	"fmt"
	"net"
	"strings"

	_ "unsafe"

	"github.com/miekg/dns"
)

var ErrNoSushHost = errors.New("lookup: no such host")

type HandlerOverHost struct {
	ttl uint32
}

func NewHandlerOverHost(ttl uint32) HandlerOverHost {
	return HandlerOverHost{
		ttl: ttl,
	}
}

func (h HandlerOverHost) Lookup(question *dns.Msg) (*dns.Msg, error) {
	qType := question.Question[0].Qtype

	switch qType {
	case dns.TypeA, dns.TypeAAAA:
		domain := question.Question[0].Name
		address := goLookupIPFiles(strings.TrimRight(domain, "."))

		if len(address) == 0 {
			return nil, ErrNoSushHost
		}

		answer := question.Copy()
		answer.SetRcode(question, dns.RcodeSuccess)
		answer.Authoritative = true
		answer.RecursionAvailable = true

		answerIP := address[0].IP
		if qType == dns.TypeA && len(answerIP) == net.IPv4len {
			answer.Answer = append(answer.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.ttl},
				A:   address[0].IP,
			})
			return answer, nil
		}

		if len(answerIP) == net.IPv6len {
			answer.Answer = append(answer.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: h.ttl},
				AAAA: address[0].IP,
			})
			return answer, nil
		}
	}

	return nil, ErrNoSushHost
}

func (h HandlerOverHost) String() string {
	return fmt.Sprintf("HOSTS[ttl: %v]", h.ttl)
}

//go:linkname goLookupIPFiles net.goLookupIPFiles
func goLookupIPFiles(name string) (addrs []net.IPAddr)
