package gateway

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

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
		if status == mcpAggregatorUpstreamNotLoaded {
			switch gw.apiDefinitionFileState(ref.APIID) {
			case apiDefinitionAwaitsReload:
				return fmt.Sprintf("aggregated MCP proxy %q is not loaded yet: reload the gateway, then retry", ref.APIID), http.StatusBadRequest
			case apiDefinitionNotLoadedByReload:
				return fmt.Sprintf("aggregated MCP proxy %q has a definition on this gateway that the last reload did not load: check the gateway log for why, fix the definition, then reload", ref.APIID), http.StatusBadRequest
			}
		}
		if msg, code := status.admissionError(ref.APIID); msg != "" {
			return msg, code
		}
	}
	return gw.validateMCPAggregatorUpstreamViews(r, &APISpec{APIDefinition: &incoming}, ext, upstreams)
}

// apiDefinitionFileState says whether the Gateway API has written a
// definition for an API that is not loaded, and whether a reload has read it.
type apiDefinitionFileState int

const (
	// apiDefinitionNoFile: no definition for the API is in the app path.
	apiDefinitionNoFile apiDefinitionFileState = iota
	// apiDefinitionAwaitsReload: the definition was written after the last
	// reload read the app path, so a reload loads it.
	apiDefinitionAwaitsReload
	// apiDefinitionNotLoadedByReload: the last reload read the definition and
	// did not load it, for example because it is invalid; another reload
	// will not change that.
	apiDefinitionNotLoadedByReload
)

// apiDefinitionFileState reports the state of the definition the Gateway API
// wrote for apiID to this gateway's app path. A definition modified before the
// last reload started reading the app path was read by that reload.
func (gw *Gateway) apiDefinitionFileState(apiID string) apiDefinitionFileState {
	if sanitize.ValidatePathComponent(apiID) != nil {
		return apiDefinitionNoFile
	}
	info, err := os.Stat(filepath.Join(gw.GetConfig().AppPath, apiID+".json"))
	if err != nil {
		return apiDefinitionNoFile
	}
	readAt := gw.apiDefinitionsReadAt.Load()
	if readAt != 0 && info.ModTime().UnixNano() < readAt {
		return apiDefinitionNotLoadedByReload
	}
	return apiDefinitionAwaitsReload
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

// mcpAggregatorWrites records, per API ID, the aggregated MCP proxies each API
// definition written through the Gateway API since the definitions the
// aggregator index was built from were read references: none for a deleted
// API or one that is not an aggregator.
type mcpAggregatorWrites struct {
	mu      sync.Mutex
	entries map[string]mcpAggregatorWrite
	// seq numbers writes in the order they were recorded.
	seq uint64
	// readSeq is seq when a reload started reading definitions, and
	// readMarked says whether that reload has not loaded them yet.
	readSeq    uint64
	readMarked bool
}

type mcpAggregatorWrite struct {
	seq   uint64
	orgID string
	refs  []string
}

// written records a definition written for apiID: def and doc are what was
// written, or nil for a delete.
func (w *mcpAggregatorWrites) written(apiID string, def *apidef.APIDefinition, doc *oas.OAS) {
	var entry mcpAggregatorWrite
	if def != nil {
		entry.orgID = def.OrgID
	}
	if def.IsMCPAggregator() && doc != nil {
		if ext := doc.GetTykMCPAggregatorExtension(); ext != nil {
			for _, ref := range ext.Upstreams {
				entry.refs = append(entry.refs, ref.APIID)
			}
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.entries == nil {
		w.entries = make(map[string]mcpAggregatorWrite)
	}
	w.seq++
	entry.seq = w.seq
	w.entries[apiID] = entry
}

// definitionsRead marks the point at which a reload reads the definitions it
// will load: writes recorded before it are in what that reload loads.
func (w *mcpAggregatorWrites) definitionsRead() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.readSeq = w.seq
	w.readMarked = true
}

// loaded drops the writes the newly loaded definitions include: the ones
// recorded before those definitions were read. Writes made while the reload
// ran stay until a reload reads them. Definitions loaded without a read
// (definitionsRead not called) are taken to include every write so far.
func (w *mcpAggregatorWrites) loaded() {
	w.mu.Lock()
	defer w.mu.Unlock()
	upTo := w.seq
	if w.readMarked {
		upTo = w.readSeq
		w.readMarked = false
	}
	for id, entry := range w.entries {
		if entry.seq <= upTo {
			delete(w.entries, id)
		}
	}
}

// orgID returns the organisation of the definition last written for apiID,
// if one was written since the definitions were read.
func (w *mcpAggregatorWrites) orgID(apiID string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry, ok := w.entries[apiID]
	return entry.orgID, ok
}

// referencing returns the sorted IDs of aggregators referencing upstreamID,
// taking loaded, the IDs from the loaded aggregators, and replacing what it
// says about any aggregator written since.
func (w *mcpAggregatorWrites) referencing(upstreamID string, loaded []string) []string {
	ids := w.collectReferencing(upstreamID, loaded)
	slices.Sort(ids)
	return ids
}

// collectReferencing gathers referencing's IDs under the lock, leaving the
// sort to run without it.
func (w *mcpAggregatorWrites) collectReferencing(upstreamID string, loaded []string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var ids []string
	for _, id := range loaded {
		if _, rewritten := w.entries[id]; !rewritten {
			ids = append(ids, id)
		}
	}
	for id, entry := range w.entries {
		if slices.Contains(entry.refs, upstreamID) {
			ids = append(ids, id)
		}
	}
	return ids
}

// mcpAggregatorUpdateConflict rejects an update that would stop aggregators
// from serving an MCP proxy they currently admit: moving it to another
// organisation, turning it into an aggregator, or making it a non-MCP API.
// Like a delete, such an update would silently drop the proxy's tools from
// those aggregators on the next reload. An aggregator the Gateway API has
// written since the last reload is judged by that write, which admission
// accepted with this proxy admitted.
func (gw *Gateway) mcpAggregatorUpdateConflict(apiID string, updated *apidef.APIDefinition, updatedOAS *oas.OAS) (string, int) {
	aggregatorIDs := gw.mcpAggregatorWrites.referencing(apiID, gw.mcpAggregatorIndex.AggregatorsReferencing(apiID))
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
		orgID, written := gw.mcpAggregatorWrites.orgID(aggregatorID)
		if !written {
			agg, ok := gw.mcpAggregatorIndex.Lookup(aggregatorID)
			if !ok || !gw.mcpAggregatorIndex.Allows(aggregatorID, apiID) {
				continue
			}
			orgID = agg.OrgID
		}
		if status := classifyMCPAggregatorUpstream(orgID, spec); status != mcpAggregatorUpstreamAdmitted {
			blocked = append(blocked, aggregatorID)
			reason = status
		}
	}
	if len(blocked) == 0 {
		return "", 0
	}
	return fmt.Sprintf("API %q is referenced by MCP aggregators: %s; after this update it %s and could no longer be aggregated", apiID, strings.Join(blocked, ", "), reason), http.StatusConflict
}
