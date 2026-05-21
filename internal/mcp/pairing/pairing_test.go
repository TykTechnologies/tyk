package pairing

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIndex_SetAndLookup(t *testing.T) {
	t.Parallel()
	idx := New()
	idx.Set(
		map[string]string{"rest-1": "rest-1__mcp-server"},
		map[string]map[string]struct{}{
			"rest-1": {"proxy-1": {}, "proxy-2": {}},
		},
	)

	assert.True(t, idx.ProxyAllowedForREST("rest-1", "proxy-1"))
	assert.True(t, idx.ProxyAllowedForREST("rest-1", "proxy-2"))
	assert.False(t, idx.ProxyAllowedForREST("rest-1", "proxy-3"))

	adapter, ok := idx.AdapterForREST("rest-1")
	assert.True(t, ok)
	assert.Equal(t, "rest-1__mcp-server", adapter)

	assert.False(t, idx.ProxyAllowedForREST("missing", "proxy-1"))
}

func TestIndex_ReplacesOnEachSet(t *testing.T) {
	t.Parallel()
	idx := New()
	idx.Set(nil, map[string]map[string]struct{}{"a": {"p1": {}}})
	idx.Set(nil, map[string]map[string]struct{}{"b": {"p2": {}}})

	assert.False(t, idx.ProxyAllowedForREST("a", "p1"), "previous mapping must be replaced wholesale")
	assert.True(t, idx.ProxyAllowedForREST("b", "p2"))

	_, ok := idx.AdapterForREST("a")
	assert.False(t, ok)
}

func TestIndex_SnapshotIsDefensive(t *testing.T) {
	t.Parallel()
	idx := New()
	idx.Set(nil, map[string]map[string]struct{}{"a": {"p": {}}})

	snap := idx.AllowedProxiesSnapshot()
	snap["a"]["p"] = false
	snap["a"]["tampered"] = true

	assert.True(t, idx.ProxyAllowedForREST("a", "p"), "mutating the snapshot must not affect the Index")
	assert.False(t, idx.ProxyAllowedForREST("a", "tampered"))
}

func TestIndex_ConcurrentReads(t *testing.T) {
	t.Parallel()
	idx := New()
	idx.Set(nil, map[string]map[string]struct{}{"x": {"p": {}}})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = idx.ProxyAllowedForREST("x", "p")
		}()
	}
	wg.Wait()
}

func TestStaticLookup(t *testing.T) {
	t.Parallel()
	var lk Lookup = Static{"rest-1": {"proxy-1": {}}}
	assert.True(t, lk.ProxyAllowedForREST("rest-1", "proxy-1"))
	assert.False(t, lk.ProxyAllowedForREST("rest-1", "proxy-2"))
}
