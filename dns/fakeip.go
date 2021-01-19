package dns

import (
	"errors"
	"net"
	"sync"
)

type fakeIPPool struct {
	mutex         sync.Mutex
	min           uint32
	max           uint32
	offset        uint32
	answerCache   map[string]uint32
	questionCache map[uint32]string
}

func newFakeIPPool(ipRange string) (*fakeIPPool, error) {
	_, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return nil, err
	}
	if len(ipNet.IP) != 4 {
		return nil, errors.New("not IPv4 range")
	}

	ones, bits := ipNet.Mask.Size()
	min := ipv4ToUint(ipNet.IP) + 2
	max := min + (1<<(bits-ones) - 2)

	p := &fakeIPPool{
		min:           min,
		max:           max,
		answerCache:   make(map[string]uint32),
		questionCache: make(map[uint32]string),
	}
	return p, nil
}

func (p *fakeIPPool) reverseLookup(ip net.IP) (string, bool) {
	if ip = ip.To4(); ip == nil {
		return "", false
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	v, ok := p.questionCache[ipv4ToUint(ip)]
	return v, ok
}

func (p *fakeIPPool) lookup(host string) net.IP {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if ip, ok := p.answerCache[host]; ok {
		return uintToIPv4(ip)
	}

	p.offset = (p.offset + 1) % (p.max - p.min)
	ipNum := p.min + p.offset - 1

	p.overwrite(ipNum, host)

	return uintToIPv4(ipNum)
}

func (p *fakeIPPool) overwrite(ipNum uint32, host string) {
	if answer := p.questionCache[ipNum]; answer != "" {
		delete(p.answerCache, answer)
	}

	p.answerCache[host] = ipNum
	p.questionCache[ipNum] = host
}

func ipv4ToUint(ip net.IP) uint32 {
	v := uint32(ip[0]) << 24
	v += uint32(ip[1]) << 16
	v += uint32(ip[2]) << 8
	v += uint32(ip[3])
	return v
}

func uintToIPv4(v uint32) net.IP {
	return net.IP{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
}
