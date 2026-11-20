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
//
// It also names the consumer the aggregator authenticated, read from the
// aggregator's own request, so the proxy's record is attributed to that
// consumer. This identity is for analytics only: the proxy's chain still runs
// under the aggregator's loop session, never the consumer's.
type mcpAggregatorOrigin struct {
	aggregatorAPIID string
	apiID           string
	consumer        mcpAggregatorConsumer
}

// mcpAggregatorConsumer is the identity an analytics record carries for the
// caller: the presented key, which the analytics writer hashes as it does for
// any record, the key alias and the OAuth client ID.
type mcpAggregatorConsumer struct {
	apiKey        string
	alias         string
	oauthClientID string
}

func ctxSetMCPAggregatorOrigin(r, parent *http.Request, trust *mcpAggregatorLoopTrust) {
	if trust == nil {
		return
	}
	origin := mcpAggregatorOrigin{aggregatorAPIID: trust.AggregatorAPIID, apiID: trust.UpstreamAPIID}
	origin.consumer.apiKey = ctxGetAuthToken(parent)
	if session := ctxGetSession(parent); session != nil {
		origin.consumer.alias = session.Alias
		origin.consumer.oauthClientID = session.OauthClientID
	}
	setCtxValue(r, mcpAggregatorOriginKey, origin)
}

// mcpAggregatorOriginOf returns the origin of a request an aggregator routed
// to apiID. Any API the aggregated proxy loops into further gets none.
func mcpAggregatorOriginOf(r *http.Request, apiID string) (mcpAggregatorOrigin, bool) {
	origin, ok := r.Context().Value(mcpAggregatorOriginKey).(mcpAggregatorOrigin)
	if !ok || origin.apiID != apiID {
		return mcpAggregatorOrigin{}, false
	}
	return origin, true
}

// recordMCPAggregatorOrigin marks the analytics record of an aggregated MCP
// proxy reached through an aggregator with that aggregator, and attributes it
// to the aggregator's consumer in place of the loop session.
func recordMCPAggregatorOrigin(rec *analytics.AnalyticsRecord, r *http.Request) {
	origin, ok := mcpAggregatorOriginOf(r, rec.APIID)
	if !ok {
		return
	}
	rec.MCPStats.AggregatorAPIID = origin.aggregatorAPIID
	rec.Tags = append(rec.Tags, mcpAggregatorAnalyticsTagPrefix+origin.aggregatorAPIID)
	// Admission probes run with no consumer and keep the loop session's key.
	if origin.consumer.apiKey != "" {
		rec.APIKey = origin.consumer.apiKey
		rec.Alias = origin.consumer.alias
		rec.OauthID = origin.consumer.oauthClientID
	}
}
