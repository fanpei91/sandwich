package dns

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	timeout = 10 * time.Second
)

var ErrLookupTimeout = errors.New("lookup timeout")

func AnswerToIP(msg *dns.Msg) net.IP {
	for _, answer := range msg.Answer {
		switch ans := answer.(type) {
		case *dns.AAAA:
			return ans.AAAA
		case *dns.A:
			return ans.A
		}
	}
	return nil
}

type HandlerOverCache struct {
	sync.RWMutex
	upstreams []Handler
	max       int
	cache     *lru.Cache
}

func NewHandlerOverCache(upstreams []Handler, max int) *HandlerOverCache {
	return &HandlerOverCache{
		upstreams: upstreams,
		max:       max,
		cache:     lru.New(max),
	}
}

func (c *HandlerOverCache) Lookup(r *dns.Msg) (*dns.Msg, error) {
	key := makeMsgAsString(r)
	c.Lock()

	Value, ok := c.cache.Get(key)
	var resolve *resolver
	if !ok {
		resolve = &resolver{}
		c.cache.Add(key, resolve)
	} else {
		resolve = Value.(*resolver)
		if resolve.finished && resolve.answer.expiredAt.Before(time.Now()) {
			resolve.finished = false
			ok = false
		}
	}

	if resolve.finished {
		c.Unlock()
		return reply(r, resolve.answer), nil
	}

	ch := make(chan answer, 1)
	resolve.waiters = append(resolve.waiters, ch)
	c.Unlock()

	if !ok {
		go c.do(key, r)
	}

	timeout := time.NewTimer(timeout)
	defer timeout.Stop()

	select {
	case answer := <-ch:
		if answer.msg != nil {
			return reply(r, answer), nil
		} else if answer.err != nil {
			return nil, answer.err
		}
	case <-timeout.C:
	}
	return nil, ErrLookupTimeout
}

func (c *HandlerOverCache) String() string {
	return "CACHE"
}

func (c *HandlerOverCache) do(key string, question *dns.Msg) {
	var expriedAt = time.Now()

	var err error
	var answer *dns.Msg
	for _, upstream := range c.upstreams {
		host := strings.TrimRight(question.Question[0].Name, ".")
		if answer, err = upstream.Lookup(question); err == nil && len(answer.Answer) > 0 {
			if ip := AnswerToIP(answer); ip != nil {
				expriedAt = expriedAt.Add(time.Duration(getTTL(answer)) * time.Second)

				logrus.Infof("dns lookup %s -> %v via %s", host, ip.String(), upstream.String())

				break
			}

		} else if err != nil {
			logrus.Warnf("failed to dns lookup %s via %s: %v", host, upstream.String(), err)
		}
	}

	c.Lock()
	defer c.Unlock()

	Value, _ := c.cache.Get(key)
	resolver := Value.(*resolver)
	resolver.finished = true
	resolver.answer.msg = answer
	resolver.answer.err = err
	resolver.answer.expiredAt = expriedAt

	for _, water := range resolver.waiters {
		water <- resolver.answer
		close(water)
	}
	resolver.waiters = nil
}

type answer struct {
	msg       *dns.Msg
	expiredAt time.Time
	err       error
}

type resolver struct {
	waiters  []chan answer
	answer   answer
	finished bool
}

func makeMsgAsString(r *dns.Msg) string {
	var question []string
	for _, q := range r.Question {
		question = append(question, q.String())
	}
	key := strings.Join(question, "")
	return key
}

func reply(question *dns.Msg, answer answer) *dns.Msg {
	msg := answer.msg.Copy()
	msg.Id = question.Id
	left := answer.expiredAt.Sub(time.Now())
	modifyTTL(msg, uint32(left/time.Second))
	return msg
}

func getTTL(msg *dns.Msg) uint32 {
	for i := range msg.Answer {
		return msg.Answer[i].Header().Ttl
	}

	return 0
}

func modifyTTL(msg *dns.Msg, ttl uint32) {
	for i := range msg.Answer {
		msg.Answer[i].Header().Ttl = ttl
	}
}
