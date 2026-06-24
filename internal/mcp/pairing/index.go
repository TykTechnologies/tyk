// Package pairing owns the runtime lookup table that connects REST source APIs,
// synthetic REST-as-MCP adapters, and the MCP proxy APIs allowed to call them.
package pairing

import (
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/TykTechnologies/tyk/internal/mcpadapter"
)

// Record is one proxy-to-source pairing discovered from loaded API specs.
type Record struct {
	SourceRESTAPIID  string
	SourceOrgID      string
	CallerProxyAPIID string
	CallerProxyOrgID string
}

// Source records the synthetic adapter and caller proxies for one REST API.
type Source struct {
	SourceRESTAPIID   string
	AdapterAPIID      string
	CallerProxyAPIIDs []string
}

// Snapshot is an immutable view of all REST-as-MCP pairings.
type Snapshot struct {
	sourcesByRESTID   map[string]Source
	sourcesByAdapter  map[string]Source
	callersByAdapter  map[string]map[string]struct{}
	referencedRESTIDs map[string]struct{}
}

// Index exposes atomic replacement and lock-free reads of the pairing snapshot.
type Index struct {
	value atomic.Value // stores Snapshot
}

// NewIndex returns an index initialized with an empty snapshot.
func NewIndex() *Index {
	idx := &Index{}
	idx.Set(Snapshot{})
	return idx
}

// CanonicalAdapterAPIID returns the runtime-only synthetic adapter ID for a
// source REST API.
func CanonicalAdapterAPIID(sourceRESTAPIID string) string {
	return sourceRESTAPIID + mcpadapter.APIIDSuffix
}

// NewSnapshot builds an immutable pairing snapshot from proxy-to-source records.
func NewSnapshot(records []Record) (Snapshot, error) {
	build := snapshotBuilder{
		sourcesByRESTID:  map[string]*sourceBuild{},
		sourceOrgByREST:  map[string]string{},
		callersByAdapter: map[string]map[string]struct{}{},
	}

	for _, record := range records {
		if err := build.add(record); err != nil {
			return Snapshot{}, err
		}
	}

	return build.snapshot(), nil
}

// Set atomically replaces the current snapshot.
func (i *Index) Set(snapshot Snapshot) {
	if i == nil {
		return
	}
	i.value.Store(snapshot.clone())
}

// Snapshot returns a defensive copy of the current snapshot.
func (i *Index) Snapshot() Snapshot {
	if i == nil {
		return Snapshot{}
	}
	return i.load().clone()
}

// LookupSource returns the source entry for a REST API ID.
func (i *Index) LookupSource(sourceRESTAPIID string) (Source, bool) {
	return i.load().LookupSource(sourceRESTAPIID)
}

// LookupAdapter returns the source entry for a synthetic adapter API ID.
func (i *Index) LookupAdapter(adapterAPIID string) (Source, bool) {
	return i.load().LookupAdapter(adapterAPIID)
}

// AllowsCaller reports whether callerProxyAPIID may invoke adapterAPIID.
func (i *Index) AllowsCaller(adapterAPIID, callerProxyAPIID string) bool {
	return i.load().AllowsCaller(adapterAPIID, callerProxyAPIID)
}

func (i *Index) load() Snapshot {
	if i == nil {
		return Snapshot{}
	}
	value := i.value.Load()
	if value == nil {
		return Snapshot{}
	}
	snapshot, ok := value.(Snapshot)
	if !ok {
		return Snapshot{}
	}
	return snapshot
}

// Sources returns all source records in deterministic source APIID order.
func (s Snapshot) Sources() []Source {
	keys := make([]string, 0, len(s.sourcesByRESTID))
	for key := range s.sourcesByRESTID {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]Source, 0, len(keys))
	for _, key := range keys {
		out = append(out, cloneSource(s.sourcesByRESTID[key]))
	}
	return out
}

// ReferencedRESTAPIIDs returns REST APIs currently referenced by paired proxies.
func (s Snapshot) ReferencedRESTAPIIDs() []string {
	ids := make([]string, 0, len(s.referencedRESTIDs))
	for id := range s.referencedRESTIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// LookupSource returns the source entry for a REST API ID.
func (s Snapshot) LookupSource(sourceRESTAPIID string) (Source, bool) {
	source, ok := s.sourcesByRESTID[sourceRESTAPIID]
	if !ok {
		return Source{}, false
	}
	return cloneSource(source), true
}

// LookupAdapter returns the source entry for a synthetic adapter API ID.
func (s Snapshot) LookupAdapter(adapterAPIID string) (Source, bool) {
	source, ok := s.sourcesByAdapter[adapterAPIID]
	if !ok {
		return Source{}, false
	}
	return cloneSource(source), true
}

// AllowsCaller reports whether callerProxyAPIID may invoke adapterAPIID.
func (s Snapshot) AllowsCaller(adapterAPIID, callerProxyAPIID string) bool {
	callers, ok := s.callersByAdapter[adapterAPIID]
	if !ok {
		return false
	}
	_, ok = callers[callerProxyAPIID]
	return ok
}

func (s Snapshot) clone() Snapshot {
	out := Snapshot{
		sourcesByRESTID:   make(map[string]Source, len(s.sourcesByRESTID)),
		sourcesByAdapter:  make(map[string]Source, len(s.sourcesByAdapter)),
		callersByAdapter:  make(map[string]map[string]struct{}, len(s.callersByAdapter)),
		referencedRESTIDs: make(map[string]struct{}, len(s.referencedRESTIDs)),
	}
	for key, source := range s.sourcesByRESTID {
		out.sourcesByRESTID[key] = cloneSource(source)
	}
	for key, source := range s.sourcesByAdapter {
		out.sourcesByAdapter[key] = cloneSource(source)
	}
	for adapterID, callers := range s.callersByAdapter {
		out.callersByAdapter[adapterID] = cloneSet(callers)
	}
	for id := range s.referencedRESTIDs {
		out.referencedRESTIDs[id] = struct{}{}
	}
	return out
}

type sourceBuild struct {
	sourceRESTAPIID string
	adapterAPIID    string
	callers         map[string]struct{}
}

type snapshotBuilder struct {
	sourcesByRESTID  map[string]*sourceBuild
	sourceOrgByREST  map[string]string
	callersByAdapter map[string]map[string]struct{}
}

func (b *snapshotBuilder) add(record Record) error {
	if record.SourceRESTAPIID == "" {
		return fmt.Errorf("pairing source REST API ID is required")
	}
	if record.CallerProxyAPIID == "" {
		return fmt.Errorf("pairing caller proxy API ID is required")
	}
	if record.SourceOrgID != "" && record.CallerProxyOrgID != "" && record.SourceOrgID != record.CallerProxyOrgID {
		return fmt.Errorf("cross-org REST-as-MCP pairing refused: source %q org %q, caller proxy %q org %q",
			record.SourceRESTAPIID, record.SourceOrgID, record.CallerProxyAPIID, record.CallerProxyOrgID)
	}
	if previousOrg, ok := b.sourceOrgByREST[record.SourceRESTAPIID]; ok && previousOrg != record.SourceOrgID {
		return fmt.Errorf("source REST API %q has inconsistent org IDs %q and %q", record.SourceRESTAPIID, previousOrg, record.SourceOrgID)
	}
	b.sourceOrgByREST[record.SourceRESTAPIID] = record.SourceOrgID

	adapterID := CanonicalAdapterAPIID(record.SourceRESTAPIID)
	source := b.sourcesByRESTID[record.SourceRESTAPIID]
	if source == nil {
		source = &sourceBuild{
			sourceRESTAPIID: record.SourceRESTAPIID,
			adapterAPIID:    adapterID,
			callers:         map[string]struct{}{},
		}
		b.sourcesByRESTID[record.SourceRESTAPIID] = source
	}

	source.callers[record.CallerProxyAPIID] = struct{}{}
	if b.callersByAdapter[adapterID] == nil {
		b.callersByAdapter[adapterID] = map[string]struct{}{}
	}
	b.callersByAdapter[adapterID][record.CallerProxyAPIID] = struct{}{}
	return nil
}

func (b *snapshotBuilder) snapshot() Snapshot {
	snapshot := Snapshot{
		sourcesByRESTID:   make(map[string]Source, len(b.sourcesByRESTID)),
		sourcesByAdapter:  make(map[string]Source, len(b.sourcesByRESTID)),
		callersByAdapter:  make(map[string]map[string]struct{}, len(b.callersByAdapter)),
		referencedRESTIDs: make(map[string]struct{}, len(b.sourcesByRESTID)),
	}

	for sourceRESTID, build := range b.sourcesByRESTID {
		source := Source{
			SourceRESTAPIID:   build.sourceRESTAPIID,
			AdapterAPIID:      build.adapterAPIID,
			CallerProxyAPIIDs: sortedSet(build.callers),
		}
		snapshot.sourcesByRESTID[sourceRESTID] = source
		snapshot.sourcesByAdapter[source.AdapterAPIID] = source
		snapshot.referencedRESTIDs[sourceRESTID] = struct{}{}
	}
	for adapterID, callers := range b.callersByAdapter {
		snapshot.callersByAdapter[adapterID] = cloneSet(callers)
	}
	return snapshot
}

func sortedSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func cloneSet(src map[string]struct{}) map[string]struct{} {
	dst := make(map[string]struct{}, len(src))
	for key := range src {
		dst[key] = struct{}{}
	}
	return dst
}

func cloneSource(source Source) Source {
	source.CallerProxyAPIIDs = append([]string(nil), source.CallerProxyAPIIDs...)
	return source
}
