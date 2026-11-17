package gateway

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
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
		if msg, code := classifyMCPAggregatorUpstream(incoming.OrgID, upstreams[i]).admissionError(ref.APIID); msg != "" {
			return msg, code
		}
	}
	return gw.validateMCPAggregatorUpstreamViews(r, &APISpec{APIDefinition: &incoming}, ext, upstreams)
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

// mcpAggregatorDeleteConflict rejects deleting an MCP proxy that aggregators
// still reference, which would silently drop their tools. An aggregator the
// Gateway API has written since the last reload is judged by that write.
func (gw *Gateway) mcpAggregatorDeleteConflict(apiID string) (interface{}, int) {
	aggregatorIDs := gw.mcpAggregatorWrites.referencing(apiID, gw.mcpAggregatorIndex.AggregatorsReferencing(apiID))
	if len(aggregatorIDs) == 0 {
		return nil, 0
	}
	return apiError(fmt.Sprintf("API %q is referenced by MCP aggregators: %s", apiID, strings.Join(aggregatorIDs, ", "))), http.StatusConflict
}

// mcpAggregatorWrites records, per API ID, the aggregated MCP proxies each MCP
// proxy definition written through the Gateway API since the last reload
// references: none for a deleted API or one that is not an aggregator.
type mcpAggregatorWrites struct {
	mu   sync.Mutex
	refs map[string][]string
}

func (w *mcpAggregatorWrites) written(apiID string, doc *oas.OAS) {
	var refs []string
	if doc != nil {
		if ext := doc.GetTykMCPAggregatorExtension(); ext != nil {
			for _, ref := range ext.Upstreams {
				refs = append(refs, ref.APIID)
			}
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.refs == nil {
		w.refs = make(map[string][]string)
	}
	w.refs[apiID] = refs
}

func (w *mcpAggregatorWrites) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.refs = nil
}

// referencing returns the sorted IDs of aggregators referencing upstreamID,
// taking loaded, the IDs from the loaded aggregators, and replacing what it
// says about any aggregator written since.
func (w *mcpAggregatorWrites) referencing(upstreamID string, loaded []string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var ids []string
	for _, id := range loaded {
		if _, rewritten := w.refs[id]; !rewritten {
			ids = append(ids, id)
		}
	}
	for id, refs := range w.refs {
		if slices.Contains(refs, upstreamID) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}
