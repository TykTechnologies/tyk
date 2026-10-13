package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/pkg/controlplane/keys"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// This file binds pkg/controlplane to the gateway runtime: loaded API specs
// become keys.APIInfo, the global session manager becomes a keys.SessionStore,
// and live config becomes keys.Config. The same package is bound by the
// Dashboard to its database and configuration, so both produce identical
// Redis state.

// gwAPIInfo exposes loaded specs as keys.APIInfoProvider.
type gwAPIInfo struct{ gw *Gateway }

func apiInfoFromSpec(spec *APISpec) keys.APIInfo {
	return keys.APIInfo{
		APIID:                                spec.APIID,
		OrgID:                                spec.OrgID,
		SessionLifetime:                      spec.SessionLifetime,
		SessionLifetimeRespectsKeyExpiration: spec.SessionLifetimeRespectsKeyExpiration,
		DontSetQuotasOnCreate:                spec.DontSetQuotasOnCreate,
		IsMCP:                                mcpProxy(spec),
	}
}

func (a gwAPIInfo) APIByID(apiID string) (keys.APIInfo, bool) {
	spec := a.gw.getApiSpec(apiID)
	if spec == nil {
		return keys.APIInfo{}, false
	}
	return apiInfoFromSpec(spec), true
}

func (a gwAPIInfo) APIsForOrg(orgID string) []keys.APIInfo {
	a.gw.apisMu.RLock()
	defer a.gw.apisMu.RUnlock()
	var out []keys.APIInfo
	for _, spec := range a.gw.apisByID {
		if spec.OrgID == orgID {
			out = append(out, apiInfoFromSpec(spec))
		}
	}
	return out
}

func (a gwAPIInfo) AllAPIs() []keys.APIInfo {
	a.gw.apisMu.RLock()
	defer a.gw.apisMu.RUnlock()
	out := make([]keys.APIInfo, 0, len(a.gw.apisByID))
	for _, spec := range a.gw.apisByID {
		out = append(out, apiInfoFromSpec(spec))
	}
	return out
}

// gwSessions exposes the (swappable) global session manager as a
// keys.SessionStore.
type gwSessions struct{ gw *Gateway }

func (s gwSessions) Store() storage.Handler { return s.gw.GlobalSessionManager.Store() }
func (s gwSessions) UpdateSession(keyName string, session *user.SessionState, resetTTLTo int64, hashed bool) error {
	return s.gw.GlobalSessionManager.UpdateSession(keyName, session, resetTTLTo, hashed)
}
func (s gwSessions) RemoveSession(orgID, keyName string, hashed bool) bool {
	return s.gw.GlobalSessionManager.RemoveSession(orgID, keyName, hashed)
}
func (s gwSessions) SessionDetail(orgID, keyName string, hashed bool) (user.SessionState, bool) {
	return s.gw.GlobalSessionManager.SessionDetail(orgID, keyName, hashed)
}
func (s gwSessions) Sessions(filter string) []string {
	return s.gw.GlobalSessionManager.Sessions(filter)
}
func (s gwSessions) ResetQuota(keyName string, session *user.SessionState, hashed bool) {
	s.gw.GlobalSessionManager.ResetQuota(keyName, session, hashed)
}

func keysConfigFromGateway(c config.Config) keys.Config {
	return keys.Config{
		HashConfig: keys.HashConfig{
			HashKeys:                    c.HashKeys,
			HashKeyFunction:             c.HashKeyFunction,
			HashKeyFunctionFallback:     c.HashKeyFunctionFallback,
			DisableKeyActionsByUsername: c.DisableKeyActionsByUsername,
			EnableKeyLogging:            c.EnableKeyLogging,
		},
		BasicAuthHashKeyFunction:             c.BasicAuthHashKeyFunction,
		MinTokenLength:                       c.MinTokenLength,
		AllowMasterKeys:                      c.AllowMasterKeys,
		EnableHashedKeysListing:              c.EnableHashedKeysListing,
		GlobalSessionLifetime:                c.GlobalSessionLifetime,
		ForceGlobalSessionLifetime:           c.ForceGlobalSessionLifetime,
		SessionLifetimeRespectsKeyExpiration: c.SessionLifetimeRespectsKeyExpiration,
	}
}

// controlPlaneKeys returns the key administration service bound to this
// gateway. It is built per call: it is a small struct over live gateway
// state (config, policies, session manager, certificate manager), all of
// which tests swap at runtime.
func (gw *Gateway) controlPlaneKeys() *keys.Service {
	return keys.New(
		func() keys.Config { return keysConfigFromGateway(gw.GetConfig()) },
		keys.Deps{
			Sessions: gwSessions{gw},
			APIs:     gwAPIInfo{gw},
			Policies: gw.policies,
			Certs:    gw.CertificateManager,
			Log:      log,
		},
	)
}

// cpResponse maps a control-plane result or error to the (object, status)
// pair the admin handlers write.
func cpResponse(obj interface{}, err error) (interface{}, int) {
	if err == nil {
		return obj, http.StatusOK
	}
	if se, ok := err.(*keys.StatusError); ok {
		return apiError(se.Message), se.Code
	}
	return apiError(err.Error()), http.StatusInternalServerError
}

// doAddOrUpdate is kept for callers inside the package (and its tests);
// the logic lives in keys.Service.AddOrUpdate.
func (gw *Gateway) doAddOrUpdate(keyName string, newSession *user.SessionState, dontReset bool, isHashed bool) error {
	return gw.controlPlaneKeys().AddOrUpdate(keyName, newSession, dontReset, isHashed)
}

// gwOrgStores resolves the per-spec org session manager the way
// getSpecForOrg does: the org's own spec, else any spec, else nothing.
type gwOrgStores struct{ gw *Gateway }

func (o gwOrgStores) OrgSessions(orgID string) (keys.SessionStore, bool) {
	spec := o.gw.getSpecForOrg(orgID)
	if spec == nil {
		return nil, false
	}
	return spec.OrgSessionManager, true
}

func orgConfigFromGateway(c config.Config) keys.OrgConfig {
	return keys.OrgConfig{HashKeys: c.HashKeys, SupressDefaultOrgStore: c.SupressDefaultOrgStore}
}

// controlPlaneOrgKeys returns the org-key service bound to this gateway.
func (gw *Gateway) controlPlaneOrgKeys() *keys.OrgService {
	return keys.NewOrgService(
		func() keys.OrgConfig { return orgConfigFromGateway(gw.GetConfig()) },
		keys.OrgDeps{
			Resolver: gwOrgStores{gw},
			Default:  &gw.DefaultOrgStore,
			Quota:    &gw.DefaultQuotaStore,
			Log:      log,
		},
	)
}
