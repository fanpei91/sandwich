// +build !darwin

package system

import "errors"

var errNotSupported = errors.New("not supported")

func setSysRoute() error {
	return errNotSupported
}

func resetSysRoute() error {
	return errNotSupported
}

func upTunIface(iface string) error {
	return errNotSupported
}

func getDNSServers(nic string) ([]string, error) {
	return nil, errNotSupported
}

func setDNSServers(servers []string, nic string) error {
	return errNotSupported
}
