package main

import (
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/fanpei91/spn/dialer"
	"github.com/fanpei91/spn/proxy"
	"github.com/fanpei91/spn/system"
	"github.com/sirupsen/logrus"
)

type flags struct {
	dnsListenAddr           string
	dnsUpstream             string
	serverMode              bool
	serverAddr              string
	listenAddr              string
	certFile                string
	privateKeyFile          string
	secretKey               string
	reversedWebsite         string
	staticDoHTTLInSeconds   uint
	rateLimitBytesPerSecond int
	outboundIface           string
	nic                     string
	enableDNSFallback       bool
	hijackDNS               bool
	logLevel                string
}

var (
	f flags
)

func main() {

	flag.BoolVar(&f.serverMode, "server-mode", false, "server mode")
	flag.StringVar(&f.serverAddr, "server-addr", "yourdomain.com:443", "the server address to connect to")
	flag.StringVar(&f.listenAddr, "listen-addr", ":443", "server listens on given address")
	flag.StringVar(&f.certFile, "cert-file", "", "cert file path")
	flag.StringVar(&f.privateKeyFile, "private-key-file", "", "private key file path")
	flag.StringVar(&f.secretKey, "secret-key", "secret key", "secrect key to cross firewall")
	flag.StringVar(&f.reversedWebsite, "reversed-website", "http://mirror.siena.edu/ubuntu/", "reversed website to fool firewall")
	flag.UintVar(&f.staticDoHTTLInSeconds, "static-doh-ttl", 86400, "use static DoH ttl")
	flag.IntVar(&f.rateLimitBytesPerSecond, "rate-limit-bytes-per-second", 20*1024*1024, "rate limit bytes per second on fooling site")
	flag.StringVar(&f.dnsUpstream, "dns-upstream", "1.1.1.1:53", "dns upstream")
	flag.StringVar(&f.dnsListenAddr, "dns-listen-addr", "127.0.0.1:53", "internal dns listen address")
	flag.StringVar(&f.outboundIface, "outbound-iface", "en0", "outbound interface to bind to")
	flag.StringVar(&f.nic, "nic", "Wi-Fi", "nic to set DNS on")
	flag.BoolVar(&f.enableDNSFallback, "enable-dns-fallback", true, "enable dns fallback when the safest dns way fails")
	flag.BoolVar(&f.hijackDNS, "hijack-dns", true, "hijack DNS")
	flag.StringVar(&f.logLevel, "log-level", "INFO", "log level: TRACE, DEBUG, INFO, WARN, ERROR, FATAL, PANIC")
	flag.Parse()

	level, err := logrus.ParseLevel(f.logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp: false,
		FullTimestamp:    true,
		TimestampFormat:  "2006-01-02 15:04:05",
	})

	if f.serverMode {
		logrus.Info("mode: server")
		logrus.Infof("listening on %s", f.listenAddr)
		logrus.Infof("cert file: %s", f.certFile)
		logrus.Infof("private key file: %s", f.privateKeyFile)
		logrus.Infof("secret key: %s", f.secretKey)
		logrus.Infof("reversed website: %s", f.reversedWebsite)
		logrus.Infof("rate limit bytes per second: %d", f.rateLimitBytesPerSecond)
		startServer()
		return
	}

	logrus.Info("mode: tun")
	logrus.Infof("server address: %s", f.serverAddr)
	logrus.Infof("secret key: %s", f.secretKey)
	logrus.Infof("static DoH TTL: %d", f.staticDoHTTLInSeconds)
	logrus.Infof("internal DNS server listen on: %s", f.dnsListenAddr)
	logrus.Infof("upstream DNS: %s", f.dnsUpstream)
	logrus.Infof("outbound interface: %s", f.outboundIface)
	logrus.Infof("nic: %s", f.nic)
	logrus.Infof("DNS fallback enabled: %v", f.enableDNSFallback)
	logrus.Infof("hijack DNS: %v", f.hijackDNS)

	dialer.Bind(f.outboundIface)

	sys, _ := system.New(
		f.nic,
		f.dnsUpstream,
		f.dnsListenAddr,
		f.secretKey,
		f.serverAddr,
		uint32(f.staticDoHTTLInSeconds),
		f.enableDNSFallback,
		f.hijackDNS,
	)

	if err := sys.Setup(); err != nil {
		sys.Destroy()
		logrus.Fatalf("%s", err.Error())
		return
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	sys.Destroy()
}

func startServer() {
	listener, err := net.Listen("tcp", f.listenAddr)
	if err != nil {
		logrus.Fatalf("server failed to listen on %s: %s", f.listenAddr, err)
	}

	server := proxy.NewFoolingServer(f.secretKey, f.reversedWebsite, f.rateLimitBytesPerSecond)
	if err := http.ServeTLS(listener, server, f.certFile, f.privateKeyFile); err != nil {
		logrus.Fatalf("server failed to start https server: %s", err)
	}
}
