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

	"github.com/TykTechnologies/tyk/config"
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

// Binding is the reverse-index value: the registry maps an api_id to the set of
// IdPs bound to it, each carrying that API's scope_to_policy overrides.
//
// A binding is self-contained: the owning Organisation, issuer and JWKS URI are
// copied from the one IdP record it was built from, so the key, issuer and
// scope mapping used for a request can never come from different records, even
// when two Organisations share a client_idp_id.
type Binding struct {
	ScopeToPolicy map[string]string
	// OrgID is the Organisation owning both the IdP and the bound API.
	OrgID   string
	IdPID   string
	Issuer  string
	JWKSURI string
	// ScopeClaimName is denormalised from the bound IdP at rebuild time so the
	// JWT hot path resolves the scope claim without a second registry lookup.
	ScopeClaimName string
	// matchedWithoutIssuer is set on the per-request copy when the token named
	// no issuer and was matched by kid (allow_unsafe_idp_missing_issuer).
	matchedWithoutIssuer bool
}

// idpKey identifies an IdP: client_idp_id is unique per Organisation only.
type idpKey struct {
	orgID string
	id    string
}

// IdPRegistry is an in-memory, request-time join of APIs to their client IdPs.
// It is a separate global on the Gateway struct, never merged into
// apidef.APIDefinition or APISpec. Its refresh mimics the API-definition load
// path across modes; the JWT path reads only the bindingsByAPI reverse index.
type IdPRegistry struct {
	gw *Gateway

	mu            sync.RWMutex // OWN mutex — never apisMu
	idps          map[idpKey]IdP
	bindingsByAPI map[string][]Binding // only index the JWT path reads

	warnedMu sync.Mutex
	// warnedMissingIssuer limits the accepted-without-issuer warning to once
	// per binding per rebuild.
	warnedMissingIssuer map[string]struct{}

	debounceMu    sync.Mutex
	debounceTimer *time.Timer
	refreshMu     sync.Mutex // serializes doRefresh

	rpcLoaderFn func() RPCDataLoader // injectable
}

func newIdPRegistry(gw *Gateway) *IdPRegistry {
	return &IdPRegistry{
		gw:            gw,
		idps:          map[idpKey]IdP{},
		bindingsByAPI: map[string][]Binding{},
		rpcLoaderFn:   func() RPCDataLoader { return &RPCStorageHandler{Gw: gw} },
	}
}

// BindingsForAPI is the hot path on JWT requests: a single RLock + map probe.
func (r *IdPRegistry) BindingsForAPI(apiID string) []Binding {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bindingsByAPI[apiID]
}

// IdP returns the IdP owned by orgID with the given client_idp_id. An empty
// orgID never matches.
func (r *IdPRegistry) IdP(orgID, idpID string) (IdP, bool) {
	if orgID == "" {
		return IdP{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	idp, ok := r.idps[idpKey{orgID: orgID, id: idpID}]
	return idp, ok
}

// allowMissingIssuer reports allow_unsafe_idp_missing_issuer; false while the
// gateway has no config loaded.
func (r *IdPRegistry) allowMissingIssuer() bool {
	conf, ok := r.gw.config.Load().(config.Config)
	return ok && conf.AllowUnsafeIDPMissingIssuer
}

// rebuild builds the reverse index, then swaps it in (build-then-swap).
//  1. Snapshot each loaded API's Organisation under a brief apisMu RLock, then
//     RELEASE apisMu before iterating idps — the hold time is
//     O(len(apisByID)), not the full rebuild cost, so it never blocks a
//     concurrent loadApps swap or reader.
//  2. Trust boundary: an IdP is bound only to loaded APIs of its own, non-empty
//     Organisation, and only when it has an issuer (unless
//     allow_unsafe_idp_missing_issuer is set). Everything else is dropped,
//     which also keeps other segments' IdP detail out of memory (IdPs with zero
//     surviving mappings are omitted). The feed is not trusted to have done
//     this: a multi-Org gateway legitimately receives every Organisation's
//     records.
//  3. Swap both maps under r.mu.Lock() — mirrors loadApps swapping apisByID.
func (r *IdPRegistry) rebuild(idps []IdP) {
	r.gw.apisMu.RLock()
	loaded := make(map[string]string, len(r.gw.apisByID))
	for id, spec := range r.gw.apisByID {
		if spec != nil && spec.APIDefinition != nil {
			loaded[id] = spec.OrgID
		} else {
			loaded[id] = ""
		}
	}
	r.gw.apisMu.RUnlock()

	allowMissingIssuer := r.allowMissingIssuer()

	byKey := make(map[idpKey]IdP, len(idps))
	bindingsByAPI := make(map[string][]Binding, len(loaded))

	for _, idp := range idps {
		if reason := idp.unusableReason(allowMissingIssuer); reason != "" {
			idpSkipLog(idp, "").Warnf("Ignoring client IdP: %s", reason)
			continue
		}
		key := idpKey{orgID: idp.OrgID, id: idp.ID}
		if _, dup := byKey[key]; dup {
			idpSkipLog(idp, "").Warn("Ignoring client IdP: duplicate ID within the Organisation")
			continue
		}

		var indexed bool
		for apiID, sm := range idp.APIMappings {
			apiOrgID, ok := loaded[apiID]
			if !ok {
				// Routine on segmented nodes, and how stale api_ids go inert.
				idpSkipLog(idp, apiID).Debug("Ignoring client IdP mapping: API not loaded")
				continue
			}
			if apiOrgID != idp.OrgID {
				idpSkipLog(idp, apiID).Warn("Ignoring client IdP mapping: API is not owned by the IdP's Organisation")
				continue
			}
			bindingsByAPI[apiID] = append(bindingsByAPI[apiID], Binding{
				OrgID:          idp.OrgID,
				IdPID:          idp.ID,
				Issuer:         idp.Issuer,
				JWKSURI:        idp.JWKSURI,
				ScopeToPolicy:  sm.ScopeToPolicy,
				ScopeClaimName: idp.ScopeClaimName,
			})
			indexed = true
		}
		if indexed {
			byKey[key] = idp
		}
	}

	r.mu.Lock()
	r.idps, r.bindingsByAPI = byKey, bindingsByAPI
	r.mu.Unlock()

	r.warnedMu.Lock()
	r.warnedMissingIssuer = nil
	r.warnedMu.Unlock()
}

// warnMissingIssuerAccepted logs, once per binding per rebuild, that a request
// was authenticated without an issuer check.
func (r *IdPRegistry) warnMissingIssuerAccepted(apiID string, b *Binding) {
	key := apiID + "\x00" + b.OrgID + "\x00" + b.IdPID

	r.warnedMu.Lock()
	_, warned := r.warnedMissingIssuer[key]
	if !warned {
		if r.warnedMissingIssuer == nil {
			r.warnedMissingIssuer = map[string]struct{}{}
		}
		r.warnedMissingIssuer[key] = struct{}{}
	}
	r.warnedMu.Unlock()

	if warned {
		return
	}
	idpSkipLog(IdP{ID: b.IdPID, OrgID: b.OrgID}, apiID).
		Warn("allow_unsafe_idp_missing_issuer: accepted a JWT without an iss claim, matched to the client IdP by key ID alone")
}

// unusableReason says why the record can never be a trust source, or returns ""
// when it can. An empty Organisation is not a wildcard, and an empty issuer
// would match tokens that name no issuer; only the latter is tolerated under
// allow_unsafe_idp_missing_issuer.
func (i IdP) unusableReason(allowMissingIssuer bool) string {
	switch {
	case i.OrgID == "":
		return "no owning Organisation"
	case i.Issuer == "" && !allowMissingIssuer:
		return "no issuer"
	default:
		return ""
	}
}

// idpSkipLog builds a registry log entry. It names records only: never tokens, JWKS URIs or key material.
func idpSkipLog(idp IdP, apiID string) *logrus.Entry {
	fields := logrus.Fields{
		"prefix":        "idp-registry",
		"client_idp_id": idp.ID,
		"org_id":        idp.OrgID,
	}
	if apiID != "" {
		fields["api_id"] = apiID
	}
	return log.WithFields(fields)
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
