package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/fanpei91/spn/dialer"
)

type Client interface {
	Dial(ctx context.Context, network string, addr string) (net.Conn, error)
}

var HTTPS = func(server, dns string, extraHeader http.Header) Client {
	return &httpsClient{
		server:      server,
		dns:         dns,
		extraHeader: extraHeader,
	}
}

type httpsClient struct {
	dns         string
	server      string
	extraHeader http.Header
}

func (t *httpsClient) Dial(ctx context.Context, network string, addr string) (net.Conn, error) {
	d, err := dialer.NewWithResolver(t.dns)
	if err != nil {
		return nil, err
	}

	tlsDialer := new(tls.Dialer)
	tlsDialer.NetDialer = d
	conn, err := tlsDialer.DialContext(ctx, "tcp", t.server)
	if err != nil {
		return nil, err
	}

	if err := t.connect(conn, network, addr); err != nil {
		return nil, err
	}

	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.ParseInt(port, 10, 32)
	return dialer.Conn{
		Conn:  conn,
		Local: conn.LocalAddr(),
		Remote: dialer.Addr{
			Net:  network,
			IP:   net.ParseIP(host),
			Port: int(p),
		},
	}, nil
}

func (t *httpsClient) connect(conn net.Conn, network, target string) error {
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\n", target)
	var header = make(http.Header, 0)
	header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36")
	header.Add("Proxy-Connection", "keep-alive")
	header.Add("Connection", "keep-alive")
	header.Add("Host", t.server)
	header.Add(HeaderNetwork, network)
	for k, values := range t.extraHeader {
		for _, v := range values {
			header.Add(k, v)
		}
	}
	header.Write(conn)
	fmt.Fprint(conn, "\r\n")

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return errors.New("connection is not established")
	}

	return nil
}
