package gateway

import (
	"github.com/sirupsen/logrus"

	mcpaggregator "github.com/TykTechnologies/tyk/internal/mcp/aggregator"
)

const mcpAggregatorUpstreamOmittedMsg = "MCP aggregator omits aggregated MCP proxy"

// computeMCPAggregation builds the aggregator index from the specs being
// loaded. Aggregated MCP proxies that cannot be served from this gateway are
// left out with a warning, so the aggregator keeps serving the others.
func computeMCPAggregation(specs []*APISpec) mcpaggregator.Snapshot {
	specsByID := make(map[string]*APISpec, len(specs))
	for _, spec := range specs {
		if spec != nil && spec.APIDefinition != nil {
			specsByID[spec.APIID] = spec
		}
	}

	aggregators := make([]mcpaggregator.Aggregator, 0)
	for _, spec := range specs {
		if spec == nil || spec.APIDefinition == nil || !spec.IsMCPAggregator() {
			continue
		}
		ext := spec.OAS.GetTykMCPAggregatorExtension()
		if ext == nil {
			continue
		}

		agg := mcpaggregator.Aggregator{APIID: spec.APIID, OrgID: spec.OrgID}
		for _, ref := range ext.Upstreams {
			agg.ReferencedAPIIDs = append(agg.ReferencedAPIIDs, ref.APIID)
			if status := classifyMCPAggregatorUpstream(spec.OrgID, specsByID[ref.APIID]); status != mcpAggregatorUpstreamAdmitted {
				logMCPAggregatorUpstreamOmitted(spec.APIID, ref.APIID, ref.Alias, status.String())
				continue
			}
			agg.Upstreams = append(agg.Upstreams, mcpaggregator.Upstream{APIID: ref.APIID, Alias: ref.Alias, Tools: ref.Tools})
		}
		aggregators = append(aggregators, agg)
	}

	return mcpaggregator.NewSnapshot(aggregators)
}

func logMCPAggregatorUpstreamOmitted(aggregatorAPIID, upstreamAPIID, alias, reason string) {
	log.WithFields(logrus.Fields{
		"aggregator_api_id": aggregatorAPIID,
		"upstream_api_id":   upstreamAPIID,
		"alias":             alias,
		"reason":            reason,
	}).Warn(mcpAggregatorUpstreamOmittedMsg)
}
