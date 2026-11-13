// Package aggregator owns the runtime lookup table that connects MCP
// aggregators to the aggregated MCP proxies they serve tools from.
package aggregator

import (
	"sort"
	"sync/atomic"
)

// NamespaceSeparator joins an upstream alias and an upstream tool name.
const NamespaceSeparator = "__"

// ToolName returns the aggregated name of an upstream tool.
func ToolName(alias, tool string) string {
	return alias + NamespaceSeparator + tool
}

// Upstream is one aggregated MCP proxy admitted for an aggregator.
type Upstream struct {
	APIID string
	Alias string
	// Tools is the configured tool selection; nil selects all tools.
	Tools []string
}

// Aggregator describes one loaded MCP aggregator.
type Aggregator struct {
	APIID string
	OrgID string
	// Upstreams are the aggregated MCP proxies admitted at load time, in
	// configured order.
	Upstreams []Upstream
	// ReferencedAPIIDs are all configured aggregated MCP proxy IDs, including
	// the ones that were not admitted at load time.
	ReferencedAPIIDs []string
}

// Snapshot is an immutable view of all loaded MCP aggregators.
type Snapshot struct {
	aggregators  map[string]Aggregator
	referencedBy map[string][]string
}

// NewSnapshot builds a snapshot from loaded aggregators.
func NewSnapshot(aggregators []Aggregator) Snapshot {
	snapshot := Snapshot{
		aggregators:  make(map[string]Aggregator, len(aggregators)),
		referencedBy: map[string][]string{},
	}
	for _, agg := range aggregators {
		snapshot.aggregators[agg.APIID] = cloneAggregator(agg)
		seen := map[string]struct{}{}
		for _, id := range agg.ReferencedAPIIDs {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			snapshot.referencedBy[id] = append(snapshot.referencedBy[id], agg.APIID)
		}
	}
	for id := range snapshot.referencedBy {
		sort.Strings(snapshot.referencedBy[id])
	}
	return snapshot
}

// Lookup returns a copy of the aggregator with the given API ID.
func (s Snapshot) Lookup(aggregatorAPIID string) (Aggregator, bool) {
	agg, ok := s.aggregators[aggregatorAPIID]
	if !ok {
		return Aggregator{}, false
	}
	return cloneAggregator(agg), true
}

// Upstream returns the admitted upstream of an aggregator by alias.
func (s Snapshot) Upstream(aggregatorAPIID, alias string) (Upstream, bool) {
	for _, upstream := range s.aggregators[aggregatorAPIID].Upstreams {
		if upstream.Alias == alias {
			return cloneUpstream(upstream), true
		}
	}
	return Upstream{}, false
}

// Allows reports whether the aggregator may call the upstream in-process.
func (s Snapshot) Allows(aggregatorAPIID, upstreamAPIID string) bool {
	for _, upstream := range s.aggregators[aggregatorAPIID].Upstreams {
		if upstream.APIID == upstreamAPIID {
			return true
		}
	}
	return false
}

// AggregatorsReferencing returns the sorted IDs of aggregators configured with
// the given aggregated MCP proxy.
func (s Snapshot) AggregatorsReferencing(upstreamAPIID string) []string {
	return append([]string(nil), s.referencedBy[upstreamAPIID]...)
}

// Index exposes atomic replacement and lock-free reads of the snapshot. The
// zero value holds an empty snapshot.
type Index struct {
	value atomic.Pointer[Snapshot]
}

// Set atomically replaces the current snapshot.
func (i *Index) Set(snapshot Snapshot) {
	i.value.Store(&snapshot)
}

// Snapshot returns the current snapshot.
func (i *Index) Snapshot() Snapshot {
	if current := i.value.Load(); current != nil {
		return *current
	}
	return Snapshot{}
}

// Lookup returns a copy of the aggregator with the given API ID.
func (i *Index) Lookup(aggregatorAPIID string) (Aggregator, bool) {
	return i.Snapshot().Lookup(aggregatorAPIID)
}

// Allows reports whether the aggregator may call the upstream in-process.
func (i *Index) Allows(aggregatorAPIID, upstreamAPIID string) bool {
	return i.Snapshot().Allows(aggregatorAPIID, upstreamAPIID)
}

// AggregatorsReferencing returns the sorted IDs of aggregators configured with
// the given aggregated MCP proxy.
func (i *Index) AggregatorsReferencing(upstreamAPIID string) []string {
	return i.Snapshot().AggregatorsReferencing(upstreamAPIID)
}

func cloneAggregator(agg Aggregator) Aggregator {
	upstreams := make([]Upstream, len(agg.Upstreams))
	for i, upstream := range agg.Upstreams {
		upstreams[i] = cloneUpstream(upstream)
	}
	agg.Upstreams = upstreams
	agg.ReferencedAPIIDs = append([]string(nil), agg.ReferencedAPIIDs...)
	return agg
}

func cloneUpstream(upstream Upstream) Upstream {
	if upstream.Tools != nil {
		upstream.Tools = append([]string{}, upstream.Tools...)
	}
	return upstream
}
