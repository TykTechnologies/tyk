// Package pairing maintains the mapping between source REST APIIDs,
// synthetic adapter APIIDs, and the MCP proxy APIIDs admitted to call them.
//
// The package is gateway-agnostic. It exposes a concrete Index struct
// (the writer side, used by the loader on every reload) and narrow
// interfaces consumed by middlewares so they can be unit-tested without
// instantiating a Gateway.
package pairing

import (
	"sort"
	"sync"
)

// AllowedProxySet maps restAPIID to the proxy APIIDs admitted to call it.
type AllowedProxySet map[string]map[string]struct{}

// Lookup answers "is this MCP proxy admitted to call that REST APIID?".
// Middlewares accept this interface so a test fake can supply a fixed mapping
// without standing up the full Gateway.
type Lookup interface {
	// ProxyAllowedForREST reports whether proxyAPIID is admitted to loop into
	// restAPIID through the shared synthetic adapter.
	ProxyAllowedForREST(restAPIID, proxyAPIID string) bool
}

// AdapterLookup answers "what is the synthetic adapter APIID paired with this
// REST APIID?". Useful for diagnostics and admin endpoints.
type AdapterLookup interface {
	AdapterForREST(restAPIID string) (adapterAPIID string, ok bool)
}

// Index is the canonical pairing store. It is safe for concurrent read after
// Set has been called; callers must not call Set concurrently with reads. The
// gateway pattern is: rebuild a fresh Index under the reload lock, then
// atomically swap.
type Index struct {
	mu sync.RWMutex

	adapter        map[string]string // restAPIID -> adapterAPIID
	allowedProxies AllowedProxySet   // restAPIID -> proxy APIID set
}

// New returns an empty Index ready for Set.
func New() *Index {
	return &Index{
		adapter:        map[string]string{},
		allowedProxies: AllowedProxySet{},
	}
}

// Set replaces both maps atomically.
func (i *Index) Set(adapter map[string]string, allowedProxies AllowedProxySet) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if adapter == nil {
		adapter = map[string]string{}
	}
	if allowedProxies == nil {
		allowedProxies = AllowedProxySet{}
	}
	i.adapter = cloneAdapterMap(adapter)
	i.allowedProxies = cloneAllowedProxySet(allowedProxies)
}

// ProxyAllowedForREST satisfies Lookup.
func (i *Index) ProxyAllowedForREST(restAPIID, proxyAPIID string) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	proxies, ok := i.allowedProxies[restAPIID]
	if !ok {
		return false
	}
	_, ok = proxies[proxyAPIID]
	return ok
}

// AdapterForREST satisfies AdapterLookup.
func (i *Index) AdapterForREST(restAPIID string) (string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	v, ok := i.adapter[restAPIID]
	return v, ok
}

// AllowedProxiesForREST returns the admitted proxy APIIDs for restAPIID in
// deterministic order.
func (i *Index) AllowedProxiesForREST(restAPIID string) ([]string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	proxies, ok := i.allowedProxies[restAPIID]
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(proxies))
	for proxyID := range proxies {
		out = append(out, proxyID)
	}
	sort.Strings(out)
	return out, true
}

// AllowedProxiesSnapshot returns a defensive copy of the allowed proxy mapping.
func (i *Index) AllowedProxiesSnapshot() map[string]map[string]bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make(map[string]map[string]bool, len(i.allowedProxies))
	for restID, proxies := range i.allowedProxies {
		out[restID] = make(map[string]bool, len(proxies))
		for proxyID := range proxies {
			out[restID][proxyID] = true
		}
	}
	return out
}

// Static is a Lookup implementation backed by a fixed map. Convenient for tests.
type Static AllowedProxySet

// ProxyAllowedForREST satisfies Lookup.
func (s Static) ProxyAllowedForREST(restAPIID, proxyAPIID string) bool {
	proxies, ok := s[restAPIID]
	if !ok {
		return false
	}
	_, ok = proxies[proxyAPIID]
	return ok
}

func cloneAdapterMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneAllowedProxySet(in AllowedProxySet) AllowedProxySet {
	out := make(AllowedProxySet, len(in))
	for restID, proxies := range in {
		out[restID] = make(map[string]struct{}, len(proxies))
		for proxyID := range proxies {
			out[restID][proxyID] = struct{}{}
		}
	}
	return out
}
