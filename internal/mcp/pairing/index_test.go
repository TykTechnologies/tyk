package pairing

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndex_SetAndLookup(t *testing.T) {
	idx := NewIndex()

	snapshot, err := NewSnapshot([]Record{
		{SourceRESTAPIID: "rest-1", SourceOrgID: "org-1", CallerProxyAPIID: "proxy-1", CallerProxyOrgID: "org-1"},
	})
	require.NoError(t, err)

	idx.Set(snapshot)

	source, ok := idx.LookupSource("rest-1")
	require.True(t, ok)
	assert.Equal(t, "rest-1", source.SourceRESTAPIID)
	assert.Equal(t, "rest-1__mcp-server", source.AdapterAPIID)
	assert.Equal(t, []string{"proxy-1"}, source.CallerProxyAPIIDs)

	byAdapter, ok := idx.LookupAdapter("rest-1__mcp-server")
	require.True(t, ok)
	assert.Equal(t, source, byAdapter)
	assert.True(t, idx.AllowsCaller("rest-1__mcp-server", "proxy-1"))
	assert.False(t, idx.AllowsCaller("rest-1__mcp-server", "proxy-2"))
}

func TestIndex_ReplacesOnEachSet(t *testing.T) {
	idx := NewIndex()

	first, err := NewSnapshot([]Record{
		{SourceRESTAPIID: "rest-1", SourceOrgID: "org-1", CallerProxyAPIID: "proxy-1", CallerProxyOrgID: "org-1"},
	})
	require.NoError(t, err)
	idx.Set(first)

	second, err := NewSnapshot([]Record{
		{SourceRESTAPIID: "rest-2", SourceOrgID: "org-1", CallerProxyAPIID: "proxy-2", CallerProxyOrgID: "org-1"},
	})
	require.NoError(t, err)
	idx.Set(second)

	_, ok := idx.LookupSource("rest-1")
	assert.False(t, ok)
	assert.False(t, idx.AllowsCaller("rest-1__mcp-server", "proxy-1"))

	source, ok := idx.LookupSource("rest-2")
	require.True(t, ok)
	assert.Equal(t, []string{"proxy-2"}, source.CallerProxyAPIIDs)
}

func TestIndex_SnapshotIsDefensive(t *testing.T) {
	snapshot, err := NewSnapshot([]Record{
		{SourceRESTAPIID: "rest-1", SourceOrgID: "org-1", CallerProxyAPIID: "proxy-b", CallerProxyOrgID: "org-1"},
		{SourceRESTAPIID: "rest-1", SourceOrgID: "org-1", CallerProxyAPIID: "proxy-a", CallerProxyOrgID: "org-1"},
	})
	require.NoError(t, err)

	sources := snapshot.Sources()
	sources[0].CallerProxyAPIIDs[0] = "mutated"

	source, ok := snapshot.LookupSource("rest-1")
	require.True(t, ok)
	assert.Equal(t, []string{"proxy-a", "proxy-b"}, source.CallerProxyAPIIDs)

	source.CallerProxyAPIIDs[0] = "mutated-again"
	source, ok = snapshot.LookupAdapter("rest-1__mcp-server")
	require.True(t, ok)
	assert.Equal(t, []string{"proxy-a", "proxy-b"}, source.CallerProxyAPIIDs)
}

func TestIndex_ConcurrentReads(t *testing.T) {
	idx := NewIndex()
	snapshot, err := NewSnapshot([]Record{
		{SourceRESTAPIID: "rest-1", SourceOrgID: "org-1", CallerProxyAPIID: "proxy-1", CallerProxyOrgID: "org-1"},
		{SourceRESTAPIID: "rest-2", SourceOrgID: "org-1", CallerProxyAPIID: "proxy-2", CallerProxyOrgID: "org-1"},
	})
	require.NoError(t, err)
	idx.Set(snapshot)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				assert.True(t, idx.AllowsCaller("rest-1__mcp-server", "proxy-1"))
				assert.False(t, idx.AllowsCaller("rest-1__mcp-server", "proxy-2"))
				_, ok := idx.LookupAdapter("rest-2__mcp-server")
				assert.True(t, ok)
			}
		}()
	}
	wg.Wait()
}

func TestNewSnapshot_CrossOrgRefused(t *testing.T) {
	_, err := NewSnapshot([]Record{
		{SourceRESTAPIID: "rest-1", SourceOrgID: "org-rest", CallerProxyAPIID: "proxy-1", CallerProxyOrgID: "org-proxy"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cross-org")
}

func TestNewSnapshot_DuplicateProxyTargetsAllowed(t *testing.T) {
	snapshot, err := NewSnapshot([]Record{
		{SourceRESTAPIID: "rest-1", SourceOrgID: "org-1", CallerProxyAPIID: "proxy-1", CallerProxyOrgID: "org-1"},
		{SourceRESTAPIID: "rest-1", SourceOrgID: "org-1", CallerProxyAPIID: "proxy-2", CallerProxyOrgID: "org-1"},
	})
	require.NoError(t, err)

	source, ok := snapshot.LookupSource("rest-1")
	require.True(t, ok)
	assert.Equal(t, []string{"proxy-1", "proxy-2"}, source.CallerProxyAPIIDs)
	assert.True(t, snapshot.AllowsCaller("rest-1__mcp-server", "proxy-1"))
	assert.True(t, snapshot.AllowsCaller("rest-1__mcp-server", "proxy-2"))
}

func TestNewSnapshot_ProxyRemovalBehavior(t *testing.T) {
	snapshot, err := NewSnapshot([]Record{
		{SourceRESTAPIID: "rest-1", SourceOrgID: "org-1", CallerProxyAPIID: "proxy-remaining", CallerProxyOrgID: "org-1"},
	})
	require.NoError(t, err)

	source, ok := snapshot.LookupSource("rest-1")
	require.True(t, ok)
	assert.Equal(t, []string{"proxy-remaining"}, source.CallerProxyAPIIDs)
	assert.False(t, snapshot.AllowsCaller("rest-1__mcp-server", "proxy-removed"))
}

func TestStaticLookup(t *testing.T) {
	snapshot, err := NewSnapshot([]Record{
		{SourceRESTAPIID: "rest-1", SourceOrgID: "org-1", CallerProxyAPIID: "proxy-1", CallerProxyOrgID: "org-1"},
	})
	require.NoError(t, err)

	assert.Equal(t, "rest-1__mcp-server", CanonicalAdapterAPIID("rest-1"))
	source, ok := snapshot.LookupAdapter(CanonicalAdapterAPIID("rest-1"))
	require.True(t, ok)
	assert.Equal(t, "rest-1", source.SourceRESTAPIID)
	assert.True(t, snapshot.AllowsCaller(CanonicalAdapterAPIID("rest-1"), "proxy-1"))
}
