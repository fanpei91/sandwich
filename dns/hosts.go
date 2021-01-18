package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	_ "unsafe"
)

type HandlerOverHost struct {
	ttl uint32
}

func NewHandlerOverHost(ttl uint32) HandlerOverHost {
	return HandlerOverHost{
		ttl: ttl,
	}
}

func (h HandlerOverHost) Lookup(_ context.Context, host string) (net.IP, time.Time) {
	res := goLookupIPFiles(host)
	if len(res) == 0 {
		return nil, time.Now()
	}

	return res[0].IP, time.Now()
}

func (h HandlerOverHost) String() string {
	return fmt.Sprintf("HOSTS[ttl: %v]", h.ttl)
}

//go:linkname goLookupIPFiles net.goLookupIPFiles
func goLookupIPFiles(name string) (addrs []net.IPAddr)
