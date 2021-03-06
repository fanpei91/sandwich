package system

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fanpei91/spn/dialer"
	"github.com/fanpei91/spn/dns"
	"github.com/fanpei91/spn/ipdb"
	"github.com/fanpei91/spn/proxy"
	"github.com/fanpei91/spn/tun"
	"github.com/fanpei91/spn/utils"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
)

const (
	gateway = "198.18.0.1"
	ipRange = "198.18.0.0/16"
)

var errNoSuchHost = errors.New("lookup: no such host")

type System struct {
	nic                string
	upstreamDNS        string
	staticDoHTTL       time.Duration
	tun                string
	secretKey          string
	serverAddr         string
	originalDNSServers []string
	dnsHijacker        *dns.Hijacker
	dnsResolver        dns.Handler
	listener           *tun.Listener
	hijackDNS          bool
	ipdbClient         *http.Client
}

func New(nic, upstreamDNS, secretKey, serverAddr string, staticDoHTTL time.Duration, enableDNSFallback, hijackDNS bool) (sys *System, err error) {
	sys = &System{
		nic:          nic,
		upstreamDNS:  upstreamDNS,
		staticDoHTTL: staticDoHTTL,
		secretKey:    secretKey,
		serverAddr:   serverAddr,
		hijackDNS:    hijackDNS,
	}
	upstreams := []dns.Handler{
		dns.NewHandlerOverHTTPS(
			staticDoHTTL,
			dns.DefaultDNSOverHTTPSProvider,
			upstreamDNS,
			5*time.Second,
			func(request *http.Request) (*url.URL, error) {
				return url.Parse("https://" + serverAddr)
			},
			http.Header{
				proxy.HeaderSecret: []string{secretKey},
			},
		),
	}
	if enableDNSFallback {
		upstreams = append(
			upstreams,
			dns.NewHandlerOverUDP(upstreamDNS, time.Second),
		)
	}

	sys.dnsResolver = dns.NewHandlerOverCache(upstreams)
	sys.dnsHijacker, _ = dns.NewHijacker(ipRange)

	sys.ipdbClient = utils.HTTPClient(
		5*time.Minute,
		func(request *http.Request) (*url.URL, error) {
			return url.Parse("https://" + serverAddr)
		},
		http.Header{
			proxy.HeaderSecret: []string{secretKey},
		},
		upstreamDNS,
	)
	return sys, nil
}

func (s *System) Setup() error {
	ns, err := getDNSServers(s.nic)
	if err != nil {
		return err
	}
	s.originalDNSServers = ns

	logrus.Debugf("original DNS list: %s", s.originalDNSServers)

	if err := s.listenTun(); err != nil {
		return err
	}

	if err := upTunIface(s.listener.Iface()); err != nil {
		return err
	}

	if err := setDNSServers([]string{"1.1.1.1"}, s.nic); err != nil {
		return err
	}

	if err := setSysRoute(); err != nil {
		return err
	}

	c := cron.New()
	c.AddFunc("@every 4h", s.pullLatestIPdb)
	c.Start()

	return nil
}

func (s *System) Destroy() error {
	resetSysRoute()
	if s.listener != nil {
		s.listener.Close()
	}
	setDNSServers(s.originalDNSServers, s.nic)
	return nil
}

func (s *System) listenTun() (err error) {
	if s.listener, err = tun.Listen(1500); err != nil {
		return err
	}

	go s.acceptUDP()
	go s.acceptTCP()

	return nil
}

func (s *System) acceptUDP() {
	var con net.Conn
	for {
		if con = s.listener.AcceptUDP(); con == nil {
			break
		}
		go s.handleUDP(con)
	}
}

func (s *System) acceptTCP() {
	var con net.Conn
	for {
		if con = s.listener.AcceptTCP(); con == nil {
			break
		}
		go s.handleTCP(con)
	}
}

func (s *System) handleTCP(tunConn net.Conn) {
	conn, domain, err := s.outboundConn(tunConn)
	if err != nil && err == errNoSuchHost {
		s.handleNoSuchHostConn(tunConn, domain)
		return
	}

	s.handleConn(conn, domain, nil)
}

func (s *System) handleUDP(tunConn net.Conn) {
	var ok bool
	if s.hijackDNS {
		if tunConn, ok = s.dnsHijacker.TryHijack(tunConn); ok {
			return
		}
	}

	conn, domain, err := s.outboundConn(tunConn)
	if err != nil && err == errNoSuchHost {
		s.handleNoSuchHostConn(tunConn, domain)
		return
	}

	s.handleConn(
		conn,
		domain,
		func(conn net.Conn) {
			conn.SetReadDeadline(
				time.Now().Add(proxy.UDPReadTimeout),
			)
		},
	)
}

func (s *System) handleNoSuchHostConn(conn net.Conn, domain string) {
	client := proxy.NewHTTPSClient(
		s.serverAddr,
		s.upstreamDNS,
		http.Header{
			proxy.HeaderSecret: []string{s.secretKey},
		},
	)
	network := conn.RemoteAddr().Network()

	_, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	addr := net.JoinHostPort(domain, port)

	logrus.Infof("%s dial %s://%s via proxy %s", conn.LocalAddr(), network, addr, client.String())

	targetConn, err := client.DialHost(context.Background(), network, addr)
	if err != nil {
		logrus.Warnf(
			"%s faield to dial %s://%s via proxy %s: %v",
			conn.LocalAddr(),
			network,
			addr,
			client.String(),
			err,
		)
		conn.Close()
		return
	}

	logrus.Infof("exchange data %s <-> %s via %s", conn.LocalAddr(), addr, client.String())

	go utils.Exchange(conn, targetConn)
	utils.Exchange(targetConn, conn)
}

func (s *System) handleConn(conn net.Conn, domain string, setReadDeadline func(conn net.Conn)) {
	targetAddr := conn.RemoteAddr().String()
	targetHost, _, _ := net.SplitHostPort(targetAddr)
	targetIP := net.ParseIP(targetHost)
	network := conn.RemoteAddr().Network()

	var client = proxy.Direct

	if !ipdb.China.Contains(targetIP) && !ipdb.Private.Contains(targetIP) {
		client = proxy.HTTPS(
			s.serverAddr,
			s.upstreamDNS,
			http.Header{
				proxy.HeaderSecret: []string{s.secretKey},
			},
		)
	}

	var targetConn net.Conn
	var err error

	if domain != "" {
		domain = fmt.Sprintf("[%s]", domain)
	}

	logrus.Infof("%s dial %s://%s%s via proxy %s", conn.LocalAddr(), conn.RemoteAddr().Network(), conn.RemoteAddr(), domain, client.String())

	if targetConn, err = client.Dial(context.Background(), network, targetAddr); err != nil {
		logrus.Warnf(
			"%s faield to dial %s://%s%s via proxy %s: %v",
			conn.LocalAddr(),
			conn.RemoteAddr().Network(),
			conn.RemoteAddr(),
			domain,
			client.String(),
			err,
		)
		conn.Close()
		return
	}

	logrus.Infof("exchange data %s <-> %s%s via proxy %s", targetConn.LocalAddr(), targetConn.RemoteAddr(), domain, client.String())

	if setReadDeadline != nil {
		setReadDeadline(conn)
	}
	go utils.Exchange(conn, targetConn)
	utils.Exchange(targetConn, conn)
}

func (s *System) outboundConn(conn net.Conn) (outConn net.Conn, domain string, err error) {
	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	ip := net.ParseIP(host)

	host, ok := s.dnsHijacker.ReverseLookup(ip)
	if !ok {
		return conn, "", nil
	}

	addr, _ := s.dnsResolver.Lookup(host)
	if addr == nil {
		return conn, host, errNoSuchHost
	}

	p, _ := strconv.ParseInt(port, 10, 32)

	return outboundConn{Conn: conn, dstAddr: addr, dstPort: int(p)}, host, nil
}

func (s *System) pullLatestIPdb() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	addr := "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	res, err := s.ipdbClient.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		logrus.Errorf("failed to request apnic: %v", err)
		return
	}

	reader := bufio.NewReader(res.Body)
	var line []byte
	var db []*ipdb.IPRange
	for {
		select {
		case <-ctx.Done():
			logrus.Errorf("timeout to pull the latest ip db")
			return
		default:
		}

		if line, _, err = reader.ReadLine(); err != nil && err == io.EOF {
			break
		} else if err != nil {
			logrus.Errorf("failed to read data from apnic: %v", err)
			return
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		parts := strings.SplitN(string(line), "|", 6)
		if len(parts) != 6 {
			continue
		}

		cc, typ, start, value := parts[1], parts[2], parts[3], parts[4]
		if !(cc == "CN" && (typ == "ipv4" || typ == "ipv6")) {
			continue
		}

		prefixLength, err := strconv.Atoi(value)
		if err != nil {
			logrus.Errorf("failed to parse prefix: %v", err)
			return
		}
		if typ == "ipv4" {
			prefixLength = 32 - int(math.Log(float64(prefixLength))/math.Log(2))
		}

		db = append(db, &ipdb.IPRange{Value: fmt.Sprintf("%s/%d", start, prefixLength)})
	}

	if len(db) == 0 {
		logrus.Errorf("got empty db")
		return
	}

	ipdb.China.Lock()
	defer ipdb.China.Unlock()
	ipdb.China.DB = db
	ipdb.China.Init()
	sort.Sort(ipdb.China)
	return
}

type outboundConn struct {
	net.Conn
	dstAddr net.IP
	dstPort int
}

func (r outboundConn) RemoteAddr() net.Addr {
	return dialer.Addr{
		IP:   r.dstAddr,
		Port: r.dstPort,
		Net:  r.Conn.RemoteAddr().Network(),
	}
}

func (r outboundConn) LocalAddr() net.Addr {
	return r.Conn.LocalAddr()
}
