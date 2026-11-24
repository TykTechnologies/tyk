package gateway

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/sanitize"
)

// validateMCPAggregatorUpstreams checks every aggregated MCP proxy of an
// incoming aggregator against the APIs loaded on this gateway. Aggregators
// call their aggregated proxies in-process, so an API this gateway has not
// loaded cannot be told apart from one that does not exist.
//
// Every aggregated MCP proxy must also serve MCP 2026-07-28, the only version
// an aggregator uses to call it, and expose every tool the aggregator selects
// from it.
func (gw *Gateway) validateMCPAggregatorUpstreams(r *http.Request, mcpObj *oas.OAS) (string, int) {
	if mcpObj == nil || mcpObj.GetTykExtension() == nil {
		return "", 0
	}
	ext := mcpObj.GetTykMCPAggregatorExtension()
	if ext == nil {
		return "", 0
	}
	if err := oas.ValidateTykMCPAggregator(ext); err != nil {
		return err.Error(), http.StatusBadRequest
	}

	var incoming apidef.APIDefinition
	mcpObj.ExtractTo(&incoming)

	gw.apisMu.RLock()
	upstreams := make([]*APISpec, len(ext.Upstreams))
	for i, ref := range ext.Upstreams {
		upstreams[i] = gw.apisByID[ref.APIID]
	}
	gw.apisMu.RUnlock()

	for i, ref := range ext.Upstreams {
		status := classifyMCPAggregatorUpstream(incoming.OrgID, upstreams[i])
		if status == mcpAggregatorUpstreamNotLoaded && gw.apiDefinitionAwaitsReload(ref.APIID) {
			return fmt.Sprintf("aggregated MCP proxy %q is not loaded yet: reload the gateway, then retry", ref.APIID), http.StatusBadRequest
		}
		if msg, code := status.admissionError(ref.APIID); msg != "" {
			return msg, code
		}
	}
	return gw.validateMCPAggregatorUpstreamViews(r, &APISpec{APIDefinition: &incoming}, ext, upstreams)
}

// apiDefinitionAwaitsReload reports whether the Gateway API has written a
// definition for apiID to this gateway's app path that it has not loaded yet.
func (gw *Gateway) apiDefinitionAwaitsReload(apiID string) bool {
	if sanitize.ValidatePathComponent(apiID) != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(gw.GetConfig().AppPath, apiID+".json"))
	return err == nil
}

// mcpAggregatorUpstreamStatus says whether an API can serve as an aggregated
// MCP proxy of an aggregator, and why not. Admission and the runtime index
// share it so they never disagree.
type mcpAggregatorUpstreamStatus int

const (
	mcpAggregatorUpstreamAdmitted mcpAggregatorUpstreamStatus = iota
	mcpAggregatorUpstreamNotLoaded
	mcpAggregatorUpstreamOtherOrg
	mcpAggregatorUpstreamIsAggregator
	mcpAggregatorUpstreamNotMCP
)

func classifyMCPAggregatorUpstream(aggregatorOrgID string, upstream *APISpec) mcpAggregatorUpstreamStatus {
	switch {
	case upstream == nil || upstream.APIDefinition == nil || upstream.IsSyntheticMCPAdapter():
		return mcpAggregatorUpstreamNotLoaded
	case upstream.OrgID != aggregatorOrgID:
		return mcpAggregatorUpstreamOtherOrg
	case upstream.IsMCPAggregator():
		return mcpAggregatorUpstreamIsAggregator
	case !upstream.IsMCPManaged():
		return mcpAggregatorUpstreamNotMCP
	}
	return mcpAggregatorUpstreamAdmitted
}

// String returns the reason logged when an aggregated MCP proxy is omitted.
func (s mcpAggregatorUpstreamStatus) String() string {
	switch s {
	case mcpAggregatorUpstreamNotLoaded:
		return "not loaded on this gateway"
	case mcpAggregatorUpstreamOtherOrg:
		return "belongs to a different organisation"
	case mcpAggregatorUpstreamIsAggregator:
		return "is an aggregator"
	case mcpAggregatorUpstreamNotMCP:
		return "is not an MCP proxy"
	}
	return ""
}

func (s mcpAggregatorUpstreamStatus) admissionError(apiID string) (string, int) {
	switch s {
	case mcpAggregatorUpstreamNotLoaded:
		return fmt.Sprintf("aggregated MCP proxy %q not found: it is not loaded on this gateway and must be deployed to the same gateway as the aggregator", apiID), http.StatusBadRequest
	case mcpAggregatorUpstreamOtherOrg:
		return fmt.Sprintf("aggregated MCP proxy %q belongs to a different organisation", apiID), http.StatusForbidden
	case mcpAggregatorUpstreamIsAggregator:
		return fmt.Sprintf("aggregated MCP proxy %q is an aggregator: an aggregator cannot aggregate another aggregator", apiID), http.StatusBadRequest
	case mcpAggregatorUpstreamNotMCP:
		return fmt.Sprintf("aggregated MCP proxy %q is not an MCP proxy: aggregated MCP proxies must be MCP proxies", apiID), http.StatusBadRequest
	}
	return "", 0
}

// validateMCPProxyReferences runs the admission checks for MCP proxies that
// reference other APIs loaded on this gateway.
func (gw *Gateway) validateMCPProxyReferences(r *http.Request, mcpObj *oas.OAS) (string, int) {
	if msg, code := gw.validatePairedMCPAdapterUpstream(r, mcpObj); msg != "" {
		return msg, code
	}
	return gw.validateMCPAggregatorUpstreams(r, mcpObj)
}

// mcpAggregatorDeleteConflict rejects deleting an MCP proxy that loaded
// aggregators still reference, which would silently drop their tools.
func (gw *Gateway) mcpAggregatorDeleteConflict(apiID string) (interface{}, int) {
	aggregatorIDs := gw.mcpAggregatorIndex.AggregatorsReferencing(apiID)
	if len(aggregatorIDs) == 0 {
		return nil, 0
	}
	return apiError(fmt.Sprintf("API %q is referenced by MCP aggregators: %s", apiID, strings.Join(aggregatorIDs, ", "))), http.StatusConflict
}

// mcpAggregatorUpdateConflict rejects an update that would stop loaded
// aggregators from serving an MCP proxy they currently admit: moving it to
// another organisation, turning it into an aggregator, or making it a non-MCP
// API. Like a delete, such an update would silently drop the proxy's tools
// from those aggregators on the next reload.
func (gw *Gateway) mcpAggregatorUpdateConflict(apiID string, updated *apidef.APIDefinition, updatedOAS *oas.OAS) (string, int) {
	aggregatorIDs := gw.mcpAggregatorIndex.AggregatorsReferencing(apiID)
	if len(aggregatorIDs) == 0 || updated == nil {
		return "", 0
	}

	spec := &APISpec{APIDefinition: updated}
	if updatedOAS != nil {
		spec.OAS = *updatedOAS
	}

	var blocked []string
	var reason mcpAggregatorUpstreamStatus
	for _, aggregatorID := range aggregatorIDs {
		agg, ok := gw.mcpAggregatorIndex.Lookup(aggregatorID)
		if !ok || !gw.mcpAggregatorIndex.Allows(aggregatorID, apiID) {
			continue
		}
		if status := classifyMCPAggregatorUpstream(agg.OrgID, spec); status != mcpAggregatorUpstreamAdmitted {
			blocked = append(blocked, aggregatorID)
			reason = status
		}
	}
	if len(blocked) == 0 {
		return "", 0
	}
	return fmt.Sprintf("API %q is referenced by MCP aggregators: %s; after this update it %s and could no longer be aggregated", apiID, strings.Join(blocked, ", "), reason), http.StatusConflict
}
