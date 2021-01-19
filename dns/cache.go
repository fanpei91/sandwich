package dns

import (
	"net"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/sirupsen/logrus"
)

const (
	timeout = time.Minute
)

type HandlerOverCache struct {
	mutext    sync.RWMutex
	upstreams []Handler
	cache     *lru.Cache
}

func NewHandlerOverCache(upstreams []Handler) *HandlerOverCache {
	d := &HandlerOverCache{
		cache:     lru.New(2 << 15),
		upstreams: upstreams,
	}
	return d
}

func (d *HandlerOverCache) Lookup(host string) (ip net.IP, expiredAt time.Time) {
	d.mutext.Lock()

	cached, ok := d.cache.Get(host)
	var resolver *dnsResolver
	if !ok {
		resolver = &dnsResolver{}
		d.cache.Add(host, resolver)
	} else {
		resolver = cached.(*dnsResolver)
		if resolver.finished && resolver.answer.expiredAt.Before(time.Now()) {
			resolver.finished = false
			ok = false
		}
	}

	if resolver.finished {
		d.mutext.Unlock()
		return resolver.answer.ip, resolver.answer.expiredAt
	}

	ch := make(chan answerCache, 1)
	resolver.waiters = append(resolver.waiters, ch)
	d.mutext.Unlock()

	if !ok {
		go d.do(host)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case answer := <-ch:
		return answer.ip, answer.expiredAt
	case <-timer.C:
		return nil, time.Now()
	}
}

func (d *HandlerOverCache) String() string {
	return "[CACHE]"
}

func (d *HandlerOverCache) do(host string) {
	var ip net.IP
	var expiredAt = time.Now()

	for _, upstream := range d.upstreams {
		ip, expiredAt = upstream.Lookup(host)
		if ip != nil {
			logrus.Infof("lookup %s -> %s via %s", host, ip, upstream.String())
			break
		}
		logrus.Warnf("failed to lookup %s via %s", host, upstream.String())
	}

	d.mutext.Lock()
	defer d.mutext.Unlock()

	cache, _ := d.cache.Get(host)
	resolver := cache.(*dnsResolver)
	resolver.finished = true
	resolver.answer.ip = ip
	resolver.answer.expiredAt = expiredAt

	for _, ch := range resolver.waiters {
		ch <- resolver.answer
		close(ch)
	}
	resolver.waiters = nil
}
