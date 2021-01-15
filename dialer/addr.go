package dialer

import (
	"fmt"
	"net"
)

type Addr struct {
	Net  string
	IP   net.IP
	Port int
}

func (t Addr) Network() string {
	return t.Net
}

func (t Addr) String() string {
	return fmt.Sprintf("%s:%d", t.IP.String(), t.Port)
}
