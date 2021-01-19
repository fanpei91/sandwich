package dialer

import (
	"fmt"
	"net"
)

type Conn struct {
	net.Conn
	Local  net.Addr
	Remote net.Addr
}

func (c Conn) LocalAddr() net.Addr {
	return c.Local
}

func (c Conn) RemoteAddr() net.Addr {
	return c.Remote
}

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
