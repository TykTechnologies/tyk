package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/rpc"
)

const idpRefreshDebounce = 100 * time.Millisecond

// IdP is a client auth IdP stored beside the API definition, joined to APIs by
// api_id. The wire shape is identical across the direct-Dashboard HTTP feed
// (GET /system/clientidps) and the MDCB/edge RPC feed (GetClientIdPs); the JSON
// tags mirror the dashboard's model.ClientIdP.
type IdP struct {
	ID      string `json:"client_idp_id"`
	OrgID   string `json:"org_id"`
	Name    string `json:"name"`
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
	// ScopeClaimName is the JWT claim that holds the OAuth scopes (e.g. "scope",
	// "scp" for Entra/Azure AD, "roles"); empty means the gateway falls back to
	// the conventional "scope" claim. Mirrors the dashboard's model.ClientIdP.
	ScopeClaimName string                  `json:"scope_claim_name"`
	APIMappings    map[string]ScopeMapping `json:"api_mappings"`
	// Shorthand duration ("2m30s"); empty selects the gateway default.
	JWKSCacheTimeout string `json:"jwks_cache_timeout"`
}

// ScopeMapping is the value type of IdP.APIMappings; the map key is the api_id.
type ScopeMapping struct {
	ScopeToPolicy map[string]string `json:"scope_to_policy"`
}

// idpFeedEnvelope is the NodeResponseOK wrapper the dashboard /system/clientidps
// HTTP feed returns ({"Status","Message":[...],"Nonce":"..."}). The RPC feed
// sends a bare array, so Nonce is only populated on the HTTP path.
type idpFeedEnvelope struct {
	Message []IdP  `json:"Message"`
	Nonce   string `json:"Nonce"`
}

// Binding is the reverse-index value: the registry maps an api_id to the IdPs
// bound to it. IdP points at the snapshot's copy of the record, shared by every
// binding of that record.
type Binding struct {
	IdP           *IdP
	JWKS          *jwksEntry // nil when the record has no usable jwks_uri
	ScopeToPolicy map[string]string
}

// client_idp_id is unique only within an org.
type idpKey struct{ OrgID, ID string }

// IdPRegistry is an in-memory, request-time join of APIs to their client IdPs.
// It is a separate global on the Gateway struct, never merged into
// apidef.APIDefinition or APISpec. Its refresh mimics the API-definition load
// path across modes; the JWT path reads only the bindingsByAPI reverse index.
type IdPRegistry struct {
	gw *Gateway

	mu            sync.RWMutex // OWN mutex — never apisMu
	bindingsByAPI map[string][]Binding
	jwksByIdP     map[idpKey]*jwksEntry
	fetcher       *jwksFetcher

	debounceMu    sync.Mutex
	debounceTimer *time.Timer
	refreshMu     sync.Mutex // serializes doRefresh

	rpcLoaderFn func() RPCDataLoader // injectable
}

func newIdPRegistry(gw *Gateway) *IdPRegistry {
	return &IdPRegistry{
		gw:            gw,
		bindingsByAPI: map[string][]Binding{},
		jwksByIdP:     map[idpKey]*jwksEntry{},
		fetcher:       &jwksFetcher{gw: gw},
		rpcLoaderFn:   func() RPCDataLoader { return &RPCStorageHandler{Gw: gw} },
	}
}

// BindingsForAPI is the hot path on JWT requests: a single RLock + map probe.
func (r *IdPRegistry) BindingsForAPI(apiID string) []Binding {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bindingsByAPI[apiID]
}

// rebuild builds the reverse index, then swaps it in. A mapping binds only when
// its API is loaded on this node (segment backstop) and belongs to the record's
// org: the direct Dashboard feed carries every org's records. Callers hold
// refreshMu, so rebuilds never overlap.
func (r *IdPRegistry) rebuild(idps []IdP) {
	b := &snapshotBuilder{
		bindingsByAPI: map[string][]Binding{},
		jwksByIdP:     map[idpKey]*jwksEntry{},
	}
	if len(idps) > 0 {
		b.orgByAPI = r.gw.loadedAPIOrgs()
		b.gwDefault = jwksDefaultTTL(r.gw.GetConfig())
		r.mu.RLock()
		b.prevJWKS = r.jwksByIdP
		r.mu.RUnlock()
	}
	for i := range idps {
		b.add(&idps[i])
	}

	r.mu.Lock()
	r.bindingsByAPI, r.jwksByIdP = b.bindingsByAPI, b.jwksByIdP
	r.mu.Unlock()
}

// snapshotBuilder is local to one rebuild call and never shared.
type snapshotBuilder struct {
	orgByAPI      map[string]string
	bindingsByAPI map[string][]Binding

	gwDefault time.Duration
	prevJWKS  map[idpKey]*jwksEntry
	jwksByIdP map[idpKey]*jwksEntry
}

func (b *snapshotBuilder) add(idp *IdP) {
	var (
		rec   *IdP
		entry *jwksEntry
	)
	for apiID, sm := range idp.APIMappings {
		org, loaded := b.orgByAPI[apiID]
		if !loaded {
			continue
		}
		if org != idp.OrgID {
			idpLog(idp).WithFields(logrus.Fields{"api_id": apiID, "api_org_id": org}).
				Warn("Ignoring client IdP mapping to an API in another org")
			continue
		}
		if rec == nil { // copy on first binding, so unbound records are not retained
			c := *idp
			rec = &c
			entry = b.jwksEntryFor(rec)
		}
		b.bindingsByAPI[apiID] = append(b.bindingsByAPI[apiID], Binding{IdP: rec, JWKS: entry, ScopeToPolicy: sm.ScopeToPolicy})
	}
}

// Returns nil for a record without a usable HTTP(S) jwks_uri.
func (b *snapshotBuilder) jwksEntryFor(idp *IdP) *jwksEntry {
	// Private hosts stay allowed (an internal Keycloak is normal); other schemes do not.
	if !httpScheme.MatchString(idp.JWKSURI) {
		idpLog(idp).Warn("Client IdP has no usable HTTP(S) jwks_uri; its tokens cannot be verified")
		return nil
	}
	ttl, source, err := idp.jwksTTL(b.gwDefault)
	if err != nil {
		idpLog(idp).WithError(err).Warn("Client IdP JWKS cache timeout")
	}

	key := idpKey{idp.OrgID, idp.ID}
	entry, carried := b.prevJWKS[key]
	if !carried || entry.url != idp.JWKSURI || entry.ttl != ttl {
		entry = newJWKSEntry(idp.JWKSURI, ttl)
		idpLog(idp).WithFields(logrus.Fields{"ttl": ttl, "source": source}).Debug("Client IdP JWKS entry created")
	}
	b.jwksByIdP[key] = entry
	return entry
}

func idpLog(idp *IdP) *logrus.Entry {
	return log.WithFields(logrus.Fields{"org_id": idp.OrgID, "client_idp_id": idp.ID})
}

func (gw *Gateway) loadedAPIOrgs() map[string]string {
	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()
	orgs := make(map[string]string, len(gw.apisByID))
	for id, spec := range gw.apisByID {
		orgs[id] = spec.OrgID
	}
	return orgs
}

func (r *IdPRegistry) flushJWKS(key idpKey) {
	r.mu.RLock()
	e := r.jwksByIdP[key]
	r.mu.RUnlock()
	if e != nil {
		e.flush()
	}
}

func (r *IdPRegistry) flushAllJWKS() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.jwksByIdP {
		e.flush()
	}
}

// refreshIdPRegistry triggers a debounced client-IdP registry refresh, guarding
// against an uninitialised registry. Used by the NoticeClientIdPChanged signal.
func (gw *Gateway) refreshIdPRegistry() {
	if gw.idpRegistry != nil {
		gw.idpRegistry.Refresh()
	}
}

// Refresh debounces a registry rebuild ~100 ms via time.AfterFunc, coalescing
// signal bursts without a goroutine/channel/library. Failures log; the previous
// snapshot stays in place.
func (r *IdPRegistry) Refresh() {
	r.debounceMu.Lock()
	defer r.debounceMu.Unlock()
	if r.debounceTimer != nil {
		r.debounceTimer.Stop()
	}
	r.debounceTimer = time.AfterFunc(idpRefreshDebounce, func() {
		if err := r.doRefresh(); err != nil {
			log.WithError(err).Error("IdP registry refresh failed")
		}
	})
}

// doRefresh is synchronous and serialized by refreshMu (debounced timers can't
// duplicate work). A cancelled gw.ctx makes a timer popping during shutdown a
// no-op. Used directly by the startup reload so the registry is ready before
// serving.
func (r *IdPRegistry) doRefresh() error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if r.gw != nil && r.gw.ctx != nil && r.gw.ctx.Err() != nil {
		return nil
	}
	idps, err := r.fetch()
	if err != nil {
		return err
	}
	r.rebuild(idps)
	return nil
}

// fetch branches on mode exactly like syncAPISpecs.
func (r *IdPRegistry) fetch() ([]IdP, error) {
	conf := r.gw.GetConfig()
	switch {
	case conf.UseDBAppConfigs:
		return r.fetchFromDashboard()
	case conf.SlaveOptions.UseRPC:
		return r.fetchFromRPC()
	default:
		return nil, nil // file mode deferred
	}
}

// fetchFromDashboard performs GET /system/clientidps via the shared dashboard
// request path (executeDashboardRequestWithRecovery), so it inherits the same
// nonce-failure re-registration and client config as FromDashboardService — the
// registry is a first-class /system/* citizen, not a fragile passive reader.
// The response is a NodeResponseOK envelope {"Status","Message":[...],"Nonce"};
// the Nonce is captured into gw.ServiceNonce so the node stays in sync — the
// dashboard rotates the node's stored nonce on every /system/* call.
func (r *IdPRegistry) fetchFromDashboard() ([]IdP, error) {
	endpoint := r.gw.buildDashboardConnStr("/system/clientidps")

	buildReq := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(r.gw.ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("build client-idps request: %w", err)
		}
		gwConfig := r.gw.GetConfig()
		req.Header.Set("authorization", gwConfig.NodeSecret)
		req.Header.Set(header.XTykNodeID, r.gw.GetNodeID())
		r.gw.ServiceNonceMutex.RLock()
		req.Header.Set(header.XTykNonce, r.gw.ServiceNonce)
		r.gw.ServiceNonceMutex.RUnlock()
		req.Header.Set(header.XTykSessionID, r.gw.SessionID)
		return req, nil
	}

	resp, err := r.gw.executeDashboardRequestWithRecovery(buildReq, "client-idps fetch")
	if err != nil {
		return nil, fmt.Errorf("client-idps fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		// Do not log the raw body of an auth failure — it may carry sensitive
		// detail. The node recovers via executeDashboardRequestWithRecovery.
		return nil, errors.New("client-idps login failure (403 Forbidden)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client-idps dashboard error: status %d", resp.StatusCode)
	}

	// Stream-decode straight off the response body to avoid buffering the whole
	// payload in memory (the registry can be large in big deployments). This path
	// can't reuse unmarshalIdPs: it must also capture the rotating Nonce, which
	// that helper deliberately drops, and it decodes from the stream rather than
	// a []byte.
	var feed idpFeedEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, fmt.Errorf("unmarshal client-idps payload: %w", err)
	}

	r.gw.ServiceNonceMutex.Lock()
	r.gw.ServiceNonce = feed.Nonce
	r.gw.ServiceNonceMutex.Unlock()

	return feed.Message, nil
}

// fetchFromRPC pulls the registry over RPC (MDCB/edge). The payload is a bare
// JSON array; an empty string is a no-op. In emergency mode (MDCB unreachable)
// it restores the registry from the Redis backup instead — mirroring how APIs
// and policies recover — and on a successful sync it refreshes that backup.
func (r *IdPRegistry) fetchFromRPC() ([]IdP, error) {
	if rpc.IsEmergencyMode() {
		return r.gw.LoadIdPsFromRPCBackup()
	}

	conf := r.gw.GetConfig()
	var tags []string
	if conf.DBAppConfOptions.NodeIsSegmented {
		tags = conf.DBAppConfOptions.Tags
	}
	payload := r.rpcLoaderFn().GetClientIdPs(conf.SlaveOptions.RPCKey, tags)
	if payload == "" {
		return nil, nil
	}
	if err := r.gw.saveRPCIdPsBackup(payload); err != nil {
		log.WithError(err).Warning("Failed to back up client-IdP registry to Redis")
	}
	return unmarshalIdPs([]byte(payload))
}

// scopeToPolicyMapForRequest merges the manual API-def scope map with the matched
// registry binding. Manual config is authoritative: on a scope-name collision
// the manual value wins, and the binding only fills scopes the manual map does
// not define. With no binding (or an empty one) the manual map is returned
// unchanged — zero allocation, byte-identical behaviour for manual APIs.
func scopeToPolicyMapForRequest(manual map[string]string, binding *Binding) map[string]string {
	if binding == nil || len(binding.ScopeToPolicy) == 0 {
		return manual
	}
	merged := make(map[string]string, len(binding.ScopeToPolicy)+len(manual))
	for s, p := range binding.ScopeToPolicy {
		merged[s] = p
	}
	for s, p := range manual {
		merged[s] = p
	}
	return merged
}

// unmarshalIdPs decodes the gateway feed payload into IdP records. It tolerates
// both transports: the RPC feed delivers a bare JSON array, while the direct-
// Dashboard HTTP feed wraps it in a NodeResponseOK envelope
// {"Status","Message":[...],"Nonce":"..."}. Empty input is a no-op.
func unmarshalIdPs(b []byte) ([]IdP, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return nil, nil
	}

	if trimmed[0] == '{' {
		var feed idpFeedEnvelope
		if err := json.Unmarshal(trimmed, &feed); err != nil {
			return nil, fmt.Errorf("unmarshal client-idps envelope: %w", err)
		}
		return feed.Message, nil
	}

	var out []IdP
	if err := json.Unmarshal(trimmed, &out); err != nil {
		return nil, fmt.Errorf("unmarshal client-idps payload: %w", err)
	}
	return out, nil
}
