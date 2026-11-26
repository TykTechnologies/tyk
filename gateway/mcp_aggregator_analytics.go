package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

const (
	mcpAggregatorOriginKey       mcpContextKey = "mcp_aggregator_origin"
	mcpAggregatorCatalogueHopKey mcpContextKey = "mcp_aggregator_catalogue_hop"

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

// ctxSetMCPAggregatorCatalogueHop marks an aggregator's internal tools/list or
// server/discover request to an aggregated MCP proxy.
//
// Unlike do-not-track, the mark only drops the analytics record of a hop the
// proxy answers: the access log, OpenTelemetry metrics and health check still
// see every hop, and a hop the proxy rejects is recorded in analytics as any
// rejected request is, so the reason a proxy dropped out of an aggregator's
// catalogue can always be traced.
func ctxSetMCPAggregatorCatalogueHop(r *http.Request) {
	setCtxValue(r, mcpAggregatorCatalogueHopKey, true)
}

func ctxIsMCPAggregatorCatalogueHop(r *http.Request) bool {
	hop, ok := r.Context().Value(mcpAggregatorCatalogueHopKey).(bool)
	return ok && hop
}

// skipsMCPAggregatorCatalogueHopRecord reports whether a completed request is
// a catalogue hop the proxy answered successfully, whose analytics record is
// dropped. A hop answered with an HTTP or JSON-RPC error is still recorded.
func skipsMCPAggregatorCatalogueHopRecord(r *http.Request, code int) bool {
	return ctxIsMCPAggregatorCatalogueHop(r) && code < http.StatusBadRequest && ctxGetJSONRPCErrorCode(r) == 0
}
