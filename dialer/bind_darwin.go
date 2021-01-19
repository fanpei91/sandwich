// +build darwin

package dialer

import (
	"net"
	"syscall"

	"github.com/sirupsen/logrus"
)

// From https://github.com/Dreamacro/clash
func Bind(ifce string) {
	hook = func(dialer *net.Dialer) error {
		iface, err := net.InterfaceByName(ifce)
		if err != nil {
			return err
		}

		dialer.Control = func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err == nil {
				ip := net.ParseIP(host)
				if ip != nil && !ip.IsGlobalUnicast() {
					logrus.Warnf("%s is not a global unicat address", ip)
					return nil
				}
			}
			return c.Control(func(fd uintptr) {
				switch network {
				case "tcp4", "udp4":
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, iface.Index)
				case "tcp6", "udp6":
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, iface.Index)
				}
			})
		}

		return nil
	}
}
