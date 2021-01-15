package ipdb

import (
	"bytes"
	"net"
	"sort"
	"sync"
)

func init() {
	Private.Init()
	sort.Sort(Private)

	China.Init()
	sort.Sort(China)
}

type IPRange struct {
	Value string
	min   net.IP
	max   net.IP
}

func (i *IPRange) init() {
	ip, inet, _ := net.ParseCIDR(i.Value)
	if len(inet.Mask) == net.IPv4len {
		ip = ip.To4()
	}

	min := ip.To4()
	if min == nil {
		min = ip.To16()
	}

	max := make([]byte, len(inet.Mask))
	for i := range inet.Mask {
		max[i] = ip[i] | ^inet.Mask[i]
	}

	i.min = min
	i.max = max
}

type IPRangeDB struct {
	sync.RWMutex
	DB []*IPRange
}

func (db *IPRangeDB) Init() {
	for i := range db.DB {
		db.DB[i].init()
	}
}

func (db *IPRangeDB) Len() int {
	return len(db.DB)
}

func (db *IPRangeDB) Less(i, j int) bool {
	return bytes.Compare(db.DB[i].max, db.DB[j].min) == -1
}

func (db *IPRangeDB) Swap(i, j int) {
	db.DB[i], db.DB[j] = db.DB[j], db.DB[i]
}

func (db *IPRangeDB) Contains(target net.IP) bool {
	db.RLock()
	defer db.RUnlock()
	if target == nil {
		return false
	}

	n := target.To4()
	if n == nil {
		n = target.To16()
	}
	target = n

	i := sort.Search(len(db.DB), func(i int) bool {
		return bytes.Compare(target, db.DB[i].min) == -1
	})

	i -= 1
	if i < 0 {
		return false
	}

	return bytes.Compare(target, db.DB[i].min) >= 0 && bytes.Compare(target, db.DB[i].max) <= 0
}
