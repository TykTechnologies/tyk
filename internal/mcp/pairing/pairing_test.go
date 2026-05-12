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
		map[string]string{"rest-1": "proxy-1"},
		map[string]string{"rest-1": "rest-1__mcp-adapter"},
	)

	proxy, ok := idx.ProxyForREST("rest-1")
	assert.True(t, ok)
	assert.Equal(t, "proxy-1", proxy)

	adapter, ok := idx.AdapterForREST("rest-1")
	assert.True(t, ok)
	assert.Equal(t, "rest-1__mcp-adapter", adapter)

	_, ok = idx.ProxyForREST("missing")
	assert.False(t, ok)
}

func TestIndex_ReplacesOnEachSet(t *testing.T) {
	t.Parallel()
	idx := New()
	idx.Set(map[string]string{"a": "p1"}, nil)
	idx.Set(map[string]string{"b": "p2"}, nil)

	_, hasA := idx.ProxyForREST("a")
	assert.False(t, hasA, "previous mapping must be replaced wholesale")

	v, ok := idx.ProxyForREST("b")
	assert.True(t, ok)
	assert.Equal(t, "p2", v)
}

func TestIndex_SnapshotIsDefensive(t *testing.T) {
	t.Parallel()
	idx := New()
	idx.Set(map[string]string{"a": "p"}, nil)

	snap := idx.PairingSnapshot()
	snap["a"] = "tampered"

	got, _ := idx.ProxyForREST("a")
	assert.Equal(t, "p", got, "mutating the snapshot must not affect the Index")
}

func TestIndex_ConcurrentReads(t *testing.T) {
	t.Parallel()
	idx := New()
	idx.Set(map[string]string{"x": "p"}, nil)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = idx.ProxyForREST("x")
		}()
	}
	wg.Wait()
}

func TestStaticLookup(t *testing.T) {
	t.Parallel()
	var lk Lookup = Static{"rest-1": "proxy-1"}
	v, ok := lk.ProxyForREST("rest-1")
	assert.True(t, ok)
	assert.Equal(t, "proxy-1", v)
}
