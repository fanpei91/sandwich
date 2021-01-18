package dns

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
)

const (
	timeout = 10 * time.Second
)

type HandlerOverCache struct {
	sync.RWMutex
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

func (d *HandlerOverCache) Lookup(ctx context.Context, host string) (ip net.IP, expriedAt time.Time) {
	d.Lock()

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
		d.Unlock()
		return resolver.answer.ip, resolver.answer.expiredAt
	}

	ch := make(chan answerCache, 1)
	resolver.waiters = append(resolver.waiters, ch)
	d.Unlock()

	if !ok {
		go d.do(ctx, host)
	}

	timeout := time.NewTimer(timeout)
	defer timeout.Stop()

	select {
	case answer := <-ch:
		return answer.ip, answer.expiredAt
	case <-timeout.C:
		return nil, time.Now()
	}
}

func (d *HandlerOverCache) String() string {
	return "[CACHE]"
}

func (d *HandlerOverCache) do(ctx context.Context, host string) {
	var ip net.IP
	var expriedAt = time.Now()

	for _, upstream := range d.upstreams {
		ip, expriedAt = upstream.Lookup(ctx, host)
		if ip != nil {
			break
		}
	}

	d.Lock()
	defer d.Unlock()

	cache, _ := d.cache.Get(host)
	resolver := cache.(*dnsResolver)
	resolver.finished = true
	resolver.answer.ip = ip
	resolver.answer.expiredAt = expriedAt

	for _, ch := range resolver.waiters {
		ch <- resolver.answer
		close(ch)
	}
	resolver.waiters = nil
}
