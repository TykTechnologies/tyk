package tykcommon

import (
	"errors"
	"sync"
)

type HostList struct {
	hMutex sync.RWMutex
	hosts  []string
}

func NewHostList() *HostList {
	thisHL := HostList{}
	thisHL.hosts = make([]string, 0)
	thisHL.hMutex = sync.RWMutex{}

	return &thisHL
}

func NewHostListFromList(newList []string) *HostList {
	thisHL := NewHostList()
	thisHL.Set(newList)

	return thisHL
}

func (h *HostList) Set(newList []string) {
	h.hMutex.Lock()
	defer h.hMutex.Unlock()

	h.hosts = newList
}

func (h *HostList) All() []string{
	return h.hosts
}

func (h *HostList) GetIndex(i int) (string, error) {
	h.hMutex.RLock()
	defer h.hMutex.RUnlock()
	if i < 0 {
		return "", errors.New("Index must be positive int")
	}

	if i > (len(h.hosts) - 1) {
		return "", errors.New("Index out of range")
	}

	return h.hosts[i], nil
}

func (h *HostList) Len() int {
	if h == nil {
		return 0
	}

	h.hMutex.RLock()
	defer h.hMutex.RUnlock()

	var thisLen int

	if h.hosts != nil {
		thisLen = len(h.hosts)
	}

	return thisLen
}
