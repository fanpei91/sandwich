// +build darwin

package system

import (
	"errors"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

var routeNets = []string{
	"1",
	"2/7",
	"4/6",
	"8/5",
	"16/4",
	"32/3",
	"64/2",
	"128.0/1",
}

func setSysRoute() error {
	for _, net := range routeNets {
		c := exec.Command("route", "add", "-net", net, gateway)

		logrus.Infoln(c.String())

		if out, err := c.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}
	}
	return nil
}

func resetSysRoute() error {
	for _, net := range routeNets {
		c := exec.Command("route", "delete", "-net", net, gateway)

		logrus.Infoln(c.String())

		if out, err := c.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}
	}
	return nil
}

func upTunIface(iface string) error {
	c := exec.Command("ifconfig", iface, gateway, "netmask", "255.255.0.0", gateway, "up")

	logrus.Infoln(c.String())

	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	return nil
}

func getDNSServers(nic string) ([]string, error) {
	c := exec.Command("networksetup", "-getdnsservers", nic)

	logrus.Infoln(c.String())

	out, err := c.CombinedOutput()
	if err != nil {
		return nil, errors.New(string(out) + err.Error())
	}
	if strings.Contains(string(out), "aren't") {
		return []string{}, nil
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

func setDNSServers(servers []string, nic string) error {
	if len(servers) != 0 {
		servers = append([]string{"-setdnsservers", nic}, servers...)
	} else {
		servers = []string{"-setdnsservers", nic, "empty"}
	}
	c := exec.Command("networksetup", servers...)

	logrus.Infoln(c.String())

	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	return nil
}
