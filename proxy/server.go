package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/fanpei91/spn/utils"
	"github.com/juju/ratelimit"
	"github.com/sirupsen/logrus"
)

const (
	HeaderSecret  = "Misha-Secret"
	HeaderNetwork = "Network"
)

const (
	UDPReadTimeout = 30 * time.Second
)

type FoolingServer struct {
	secretKey               string
	reversedWebsite         string
	rateLimitBytesPerSecond int
}

func NewFoolingServer(secretKey, reversedWebsite string, rateLimitBytesPerSecond int) *FoolingServer {
	return &FoolingServer{
		secretKey:               secretKey,
		reversedWebsite:         reversedWebsite,
		rateLimitBytesPerSecond: rateLimitBytesPerSecond,
	}
}

func (s *FoolingServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get(HeaderSecret) == s.secretKey {
		s.crossWall(rw, req)
		return
	}
	s.reverseProxy(rw, req)
}

func (s *FoolingServer) crossWall(rw http.ResponseWriter, req *http.Request) {
	var target net.Conn
	var err error

	targetAddr := appendPort(req.Host, req.URL.Scheme)
	network := req.Header.Get(HeaderNetwork)
	if network == "" {
		network = "tcp"
	}

	dialer := new(net.Dialer)

	logrus.Infof("%s dial %s://%s", req.RemoteAddr, network, targetAddr)

	target, err = dialer.DialContext(req.Context(), network, targetAddr)
	if err != nil {
		logrus.Infof("%s failed to dial %s://%s: %v", req.RemoteAddr, network, targetAddr, err)
		http.Error(rw, err.Error(), http.StatusServiceUnavailable)
		return
	}

	clean(req)

	client, _, _ := rw.(http.Hijacker).Hijack()
	if req.Method == http.MethodConnect {
		client.Write([]byte(fmt.Sprintf("%s 200 OK\r\n\r\n", req.Proto)))
	} else {
		req.Write(target)
	}

	if network == "udp" || network == "udp4" || network == "udp6" {
		target.SetReadDeadline(time.Now().Add(UDPReadTimeout))
	}

	go utils.Exchange(client, target)
	utils.Exchange(target, client)
}

func (s *FoolingServer) reverseProxy(rw http.ResponseWriter, req *http.Request) {
	logrus.Infof("serve the content of %s for %s", s.reversedWebsite, req.RemoteAddr)

	var u *url.URL
	var err error
	if u, err = url.Parse(s.reversedWebsite); err != nil {
		logrus.Fatalf("%v", err)
		return
	}

	clean(req)

	req.URL.Host = u.Host
	req.URL.Scheme = u.Scheme
	req.Host = ""
	if s.rateLimitBytesPerSecond > 0 {
		rw = newRateLimitResponseWriter(rw, s.rateLimitBytesPerSecond)
	}
	httputil.NewSingleHostReverseProxy(u).ServeHTTP(rw, req)
}

func clean(req *http.Request) {
	req.Header.Del(HeaderNetwork)
	req.Header.Del(HeaderSecret)
}

type rateLimitResponseWriter struct {
	rw      http.ResponseWriter
	limiter io.Writer
}

func newRateLimitResponseWriter(rw http.ResponseWriter, rateLimitBytesPerSeconds int) *rateLimitResponseWriter {
	bucket := ratelimit.NewBucketWithRate(float64(rateLimitBytesPerSeconds), int64(rateLimitBytesPerSeconds))
	w := ratelimit.Writer(rw, bucket)
	return &rateLimitResponseWriter{
		rw:      rw,
		limiter: w,
	}
}

func (r *rateLimitResponseWriter) Header() http.Header {
	return r.rw.Header()
}

func (r *rateLimitResponseWriter) Write(p []byte) (int, error) {
	return r.limiter.Write(p)
}

func (r *rateLimitResponseWriter) WriteHeader(statusCode int) {
	r.rw.WriteHeader(statusCode)
}

func appendPort(host string, schema string) string {
	if strings.Index(host, ":") < 0 || strings.HasSuffix(host, "]") {
		if schema == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host
}
