package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

const (
	mcpAggregatorOriginKey mcpContextKey = "mcp_aggregator_origin"

	// mcpAggregatorAnalyticsTagPrefix prefixes the analytics tag naming the
	// aggregator that routed a request to an aggregated MCP proxy.
	mcpAggregatorAnalyticsTagPrefix = "mcp-aggregator-"
)

// mcpAggregatorOrigin names the aggregator that routed an internal request to
// one of its aggregated MCP proxies, for that proxy's analytics. The
// dispatcher sets it from the loop trust it hands the proxy's chain, in the
// internal request's context, so it never comes from anything a client sends
// and every copy of the request made in the chain carries it.
type mcpAggregatorOrigin struct {
	aggregatorAPIID string
	apiID           string
}

func ctxSetMCPAggregatorOrigin(r *http.Request, trust *mcpAggregatorLoopTrust) {
	if trust == nil {
		return
	}
	setCtxValue(r, mcpAggregatorOriginKey, mcpAggregatorOrigin{aggregatorAPIID: trust.AggregatorAPIID, apiID: trust.UpstreamAPIID})
}

// mcpAggregatorOriginOf returns the aggregator that routed this request to
// apiID. Any API the aggregated proxy loops into further gets none.
func mcpAggregatorOriginOf(r *http.Request, apiID string) string {
	origin, ok := r.Context().Value(mcpAggregatorOriginKey).(mcpAggregatorOrigin)
	if !ok || origin.apiID != apiID {
		return ""
	}
	return origin.aggregatorAPIID
}

// recordMCPAggregatorOrigin marks the analytics record of an aggregated MCP
// proxy reached through an aggregator with that aggregator.
func recordMCPAggregatorOrigin(rec *analytics.AnalyticsRecord, r *http.Request) {
	aggregatorAPIID := mcpAggregatorOriginOf(r, rec.APIID)
	if aggregatorAPIID == "" {
		return
	}
	rec.MCPStats.AggregatorAPIID = aggregatorAPIID
	rec.Tags = append(rec.Tags, mcpAggregatorAnalyticsTagPrefix+aggregatorAPIID)
}
