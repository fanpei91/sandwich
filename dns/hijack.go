package dns

import (
	"net"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Hijacker struct {
	pool  *fakeIPPool
	mutex sync.Mutex
	hosts HandlerOverHost
}

func NewHijacker(ipRange string) (*Hijacker, error) {
	p, err := newFakeIPPool(ipRange)
	if err != nil {
		return nil, err
	}

	return &Hijacker{
		pool:  p,
		hosts: NewHandlerOverHost(0),
	}, nil
}

func (h *Hijacker) TryHijack(conn net.Conn) (net.Conn, bool) {
	if _, port, _ := net.SplitHostPort(conn.RemoteAddr().String()); port != "53" {
		return conn, false
	}

	buf := pool.Get(512) // DNS query max size is 512
	defer pool.Put(buf)

	n, err := conn.Read(buf)
	if err != nil {
		logrus.Errorf("got error while hijacking connection %v: %v", conn.RemoteAddr(), err)
		return nil, true
	}

	question := new(dns.Msg)

	if err := question.Unpack(buf[:n]); err != nil {
		read := make([]byte, n)
		copy(read, buf[:n])
		return &readConn{
			Conn: conn,
			read: read,
		}, false
	}

	h.ServeDNS(dnsResponseWriter{Conn: conn}, question)

	return nil, true
}

func (h *Hijacker) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	answer := r.Copy()
	answer.SetRcode(r, dns.RcodeSuccess)
	answer.Authoritative = true
	answer.RecursionAvailable = true

	for _, question := range r.Question {
		domain := question.Name
		host := strings.TrimRight(domain, ".")

		ip, _ := h.hosts.Lookup(host)
		if ip != nil {
			answer.Answer = append(answer.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: ipToType(ip), Class: dns.ClassINET, Ttl: 0},
				A:   ip,
			})
			logrus.Infof("dns hijack %s -> %s in hosts", host, ip)
			continue
		}

		if !strings.Contains(host, ".") {
			logrus.Debugf("dns hijacking detection: %s", host)
			handleFailed(w, r, dns.RcodeNameError)
			return
		}

		ip = h.pool.lookup(host)
		answer.Answer = append(answer.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: ipToType(ip), Class: dns.ClassINET, Ttl: 0},
			A:   ip,
		})

		logrus.Infof("dns hijack %s -> %s in fakeip", host, ip)
	}

	w.WriteMsg(answer)
}

func (h *Hijacker) ReverseLookup(ip net.IP) (string, bool) {
	return h.pool.reverseLookup(ip)
}

func handleFailed(w dns.ResponseWriter, r *dns.Msg, code int) {
	m := new(dns.Msg)
	m.SetRcode(r, code)
	w.WriteMsg(m)
}

func ipToType(ip net.IP) uint16 {
	if len(ip) == net.IPv4len {
		return dns.TypeA
	}
	if len(ip) == net.IPv6len {
		return dns.TypeAAAA
	}
	return dns.TypeNone
}

type dnsResponseWriter struct {
	net.Conn
}

func (d dnsResponseWriter) WriteMsg(msg *dns.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}

	_, err = d.Conn.Write(data)
	return err
}

func (d dnsResponseWriter) TsigStatus() error {
	return nil
}

func (d dnsResponseWriter) TsigTimersOnly(bool) {

}

func (d dnsResponseWriter) Hijack() {

}

type readConn struct {
	net.Conn
	read []byte
}

func (c *readConn) Read(b []byte) (n int, err error) {
	if len(c.read) != 0 {
		n = copy(b, c.read)
		if n <= len(c.read) {
			c.read = c.read[n:]
			return n, nil
		}
	}

	n1, err := c.Conn.Read(b[n:])
	return n + n1, err
}
