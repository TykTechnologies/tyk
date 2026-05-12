// Package pairing maintains the 1:1 mapping between an MCP proxy APIID
// and the source REST APIID it loops into via a synthetic adapter.
//
// The package is gateway-agnostic. It exposes a concrete Index struct
// (the writer side, used by the loader on every reload) and two narrow
// interfaces (Lookup, AdapterLookup) consumed by middlewares and admit-
// time validators so they can be unit-tested without instantiating a
// Gateway.
package pairing

import "sync"

// Lookup answers "is this REST APIID paired with that MCP proxy?".
// Middlewares accept this interface so a test fake can supply a fixed
// mapping without standing up the full Gateway.
type Lookup interface {
	// ProxyForREST returns the operator-managed MCP proxy APIID that is
	// admitted to loop into the given REST APIID, and a bool indicating
	// whether any pairing was recorded.
	ProxyForREST(restAPIID string) (proxyAPIID string, ok bool)
}

// AdapterLookup answers "what is the synthetic adapter APIID paired
// with this REST APIID?". Useful for diagnostics and admin endpoints.
type AdapterLookup interface {
	AdapterForREST(restAPIID string) (adapterAPIID string, ok bool)
}

// Index is the canonical pairing store. It is safe for concurrent read
// after Set has been called; callers must not call Set concurrently
// with reads. The gateway pattern is: rebuild a fresh Index under the
// reload lock, then atomically swap.
type Index struct {
	mu      sync.RWMutex
	pairing map[string]string // restAPIID → proxyAPIID
	adapter map[string]string // restAPIID → adapterAPIID
}

// New returns an empty Index ready for Set.
func New() *Index {
	return &Index{
		pairing: map[string]string{},
		adapter: map[string]string{},
	}
}

// Set replaces both maps atomically. The maps are taken over by the
// Index; callers must not retain references.
func (i *Index) Set(pairing, adapter map[string]string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if pairing == nil {
		pairing = map[string]string{}
	}
	if adapter == nil {
		adapter = map[string]string{}
	}
	i.pairing = pairing
	i.adapter = adapter
}

// ProxyForREST satisfies Lookup.
func (i *Index) ProxyForREST(restAPIID string) (string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	v, ok := i.pairing[restAPIID]
	return v, ok
}

// AdapterForREST satisfies AdapterLookup.
func (i *Index) AdapterForREST(restAPIID string) (string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	v, ok := i.adapter[restAPIID]
	return v, ok
}

// PairingSnapshot returns a defensive copy of the proxy mapping. Used
// by validateMCP at admit time to enforce the 1:1 invariant.
func (i *Index) PairingSnapshot() map[string]string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make(map[string]string, len(i.pairing))
	for k, v := range i.pairing {
		out[k] = v
	}
	return out
}

// Static is a Lookup implementation backed by a fixed map. Convenient
// for tests.
type Static map[string]string

// ProxyForREST satisfies Lookup.
func (s Static) ProxyForREST(restAPIID string) (string, bool) {
	v, ok := s[restAPIID]
	return v, ok
}
