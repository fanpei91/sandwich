package dns

import (
	"github.com/miekg/dns"
)

type Server struct {
	handler Handler
	addr    string
}

func New(h Handler, addr string) *Server {
	return &Server{
		handler: h,
		addr:    addr,
	}
}

func (s *Server) Listen() error {
	return dns.ListenAndServe(s.addr, "udp", s)
}

func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	answer, err := s.handler.Lookup(r)
	if err != nil {
		handleFailed(w, r, dns.RcodeServerFailure)
		return
	}
	w.WriteMsg(answer)
}
