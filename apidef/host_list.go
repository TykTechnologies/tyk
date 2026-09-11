package apidef

import (
	"errors"
	"sync"
)

type HostList struct {
	hMutex sync.RWMutex
	hosts  []string
}

func NewHostList() *HostList {
	hl := HostList{}
	hl.hosts = make([]string, 0)
	return &hl
}

func NewHostListFromList(newList []string) *HostList {
	hl := NewHostList()
	hl.Set(newList)
	return hl
}

func (h *HostList) Set(newList []string) {
	h.hMutex.Lock()
	defer h.hMutex.Unlock()

	h.hosts = newList
}

// All returns a copy of the host list. The copy matters: the list is now
// rewritten in place by the upstream DNS poller while requests are reading it,
// so handing out the backing slice would let a caller range over it while Set
// swaps it underneath.
func (h *HostList) All() []string {
	h.hMutex.RLock()
	defer h.hMutex.RUnlock()

	out := make([]string, len(h.hosts))
	copy(out, h.hosts)
	return out
}

func (h *HostList) GetIndex(i int) (string, error) {
	if i < 0 {
		return "", errors.New("index must be positive int")
	}
	h.hMutex.RLock()
	defer h.hMutex.RUnlock()

	if i > len(h.hosts)-1 {
		return "", errors.New("index out of range")
	}

	return h.hosts[i], nil
}

func (h *HostList) Len() int {
	h.hMutex.RLock()
	defer h.hMutex.RUnlock()
	return len(h.hosts)
}
