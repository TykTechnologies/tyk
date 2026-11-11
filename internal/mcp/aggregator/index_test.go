package aggregator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func companyTools() Aggregator {
	return Aggregator{
		APIID: "company-tools",
		OrgID: "acme",
		Upstreams: []Upstream{
			{APIID: "orders-mcp", Alias: "orders", Tools: []string{"list_orders"}},
			{APIID: "github-mcp", Alias: "github"},
		},
		ReferencedAPIIDs: []string{"orders-mcp", "github-mcp", "eu-orders-mcp"},
	}
}

func TestSnapshotLooksUpAdmittedUpstreamsInConfiguredOrder(t *testing.T) {
	snapshot := NewSnapshot([]Aggregator{companyTools()})

	agg, ok := snapshot.Lookup("company-tools")
	require.True(t, ok)
	assert.Equal(t, "acme", agg.OrgID)
	assert.Equal(t, []Upstream{
		{APIID: "orders-mcp", Alias: "orders", Tools: []string{"list_orders"}},
		{APIID: "github-mcp", Alias: "github"},
	}, agg.Upstreams)

	upstream, ok := snapshot.Upstream("company-tools", "github")
	require.True(t, ok)
	assert.Equal(t, "github-mcp", upstream.APIID)

	assert.True(t, snapshot.Allows("company-tools", "orders-mcp"))
	assert.False(t, snapshot.Allows("company-tools", "eu-orders-mcp"), "configured but not admitted upstreams are not callable")
	assert.False(t, snapshot.Allows("other", "orders-mcp"))

	_, ok = snapshot.Lookup("missing")
	assert.False(t, ok)
}

func TestSnapshotReportsAggregatorsReferencingAnUpstream(t *testing.T) {
	second := Aggregator{APIID: "all-tools", OrgID: "acme", ReferencedAPIIDs: []string{"github-mcp"}}
	snapshot := NewSnapshot([]Aggregator{companyTools(), second})

	assert.Equal(t, []string{"all-tools", "company-tools"}, snapshot.AggregatorsReferencing("github-mcp"))
	assert.Equal(t, []string{"company-tools"}, snapshot.AggregatorsReferencing("eu-orders-mcp"))
	assert.Empty(t, snapshot.AggregatorsReferencing("payments-rest"))
}

func TestIndexReplacesSnapshotAtomicallyAndCopiesDefensively(t *testing.T) {
	var idx Index
	assert.Empty(t, idx.AggregatorsReferencing("github-mcp"), "zero value index is usable")

	idx.Set(NewSnapshot([]Aggregator{companyTools()}))
	agg, ok := idx.Lookup("company-tools")
	require.True(t, ok)
	agg.Upstreams[0].Alias = "mutated"
	agg.Upstreams[0].Tools[0] = "mutated"

	again, _ := idx.Lookup("company-tools")
	assert.Equal(t, "orders", again.Upstreams[0].Alias)
	assert.Equal(t, []string{"list_orders"}, again.Upstreams[0].Tools)

	idx.Set(NewSnapshot(nil))
	_, ok = idx.Lookup("company-tools")
	assert.False(t, ok)
	assert.False(t, idx.Allows("company-tools", "orders-mcp"))
}

func TestToolName(t *testing.T) {
	assert.Equal(t, "orders__list_orders", ToolName("orders", "list_orders"))
}
