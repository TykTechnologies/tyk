package httputil

import (
	"net/http"
	"sync"
)

// TransportPool holds a map of *http.Transport values.
type TransportPool struct {
	mu   sync.RWMutex
	pool map[string]*http.Transport
}

// NewTransportPool creates a new *TransportPool.
func NewTransportPool() *TransportPool {
	return &TransportPool{
		pool: make(map[string]*http.Transport),
	}
}

// Put will set or replace transport by key. If a transport already exists,
// the function will call CloseIdleConnections before replacing it.
// It returns the *http.Transport that was just put into the pool.
func (tp *TransportPool) Put(key string, transport *http.Transport) *http.Transport {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	prev, ok := tp.pool[key]

	tp.pool[key] = transport

	if ok {
		defer func() {
			go prev.CloseIdleConnections()
		}()
	}

	return transport
}

// Get returns a transport for a key. Returns nil if no transport found.
func (tp *TransportPool) Get(key string) *http.Transport {
	tp.mu.RLock()
	val, _ := tp.pool[key]
	tp.mu.RUnlock()
	return val
}

// CloseIdleConnections invokes CloseIdleConnections on all tracked transports.
func (tp *TransportPool) CloseIdleConnections() {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	tp.closeIdleConnections()
}

func (tp *TransportPool) closeIdleConnections() {
	for _, conn := range tp.pool {
		// Prevent new idle connections to be generated.
		conn.DisableKeepAlives = true
		conn.CloseIdleConnections()
	}
}

// Clear clears the pool invoking CloseIdleConnections as it goes.
func (tp *TransportPool) Clear() {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	tp.clear()
}

func (tp *TransportPool) clear() {
	tp.closeIdleConnections()

	for key, _ := range tp.pool {
		delete(tp.pool, key)
	}
}
