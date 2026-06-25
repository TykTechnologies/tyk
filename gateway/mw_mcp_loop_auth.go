package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

type MCPLoopAuthBypassMiddleware struct {
	*BaseMiddleware
}

func (m *MCPLoopAuthBypassMiddleware) Name() string {
	return "MCPLoopAuthBypassMiddleware"
}

func (m *MCPLoopAuthBypassMiddleware) EnabledForSpec() bool {
	return mcpLoopAuthEnabledForSpec(m.Spec)
}

//nolint:staticcheck // ST1008: middleware interface requires (error, int).
func (m *MCPLoopAuthBypassMiddleware) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	trust, ok := ctxGetMCPAdapterLoopTrust(r)
	if !ok {
		return nil, http.StatusOK
	}

	if !m.validLoopTrust(trust) {
		m.logInvalidLoopTrust(trust)
		return errMCPLoopTrustMismatch, http.StatusForbidden
	}

	m.installLoopSession(r, trust)
	ctxSetMCPAdapterLoopAuthBypassed(r, true)
	ctxSetRequestStatus(r, StatusOkAndIgnore)
	return nil, http.StatusOK
}

func (m *MCPLoopAuthBypassMiddleware) validLoopTrust(trust mcpAdapterLoopTrust) bool {
	if m == nil || m.Spec == nil || m.Gw == nil {
		return false
	}
	if trust.SourceRESTAPIID == "" || trust.AdapterAPIID == "" || trust.CallerProxyAPIID == "" {
		return false
	}
	if trust.SourceRESTAPIID != m.Spec.APIID {
		return false
	}

	source, ok := m.Gw.mcpPairingIndex.LookupAdapter(trust.AdapterAPIID)
	if !ok {
		return false
	}
	if source.SourceRESTAPIID != trust.SourceRESTAPIID || source.AdapterAPIID != trust.AdapterAPIID {
		return false
	}
	return m.Gw.mcpPairingIndex.AllowsCaller(trust.AdapterAPIID, trust.CallerProxyAPIID)
}

func (m *MCPLoopAuthBypassMiddleware) logInvalidLoopTrust(trust mcpAdapterLoopTrust) {
	if m == nil {
		return
	}
	restAPIID := ""
	if m.Spec != nil {
		restAPIID = m.Spec.APIID
	}
	m.Logger().WithFields(map[string]interface{}{
		"rest_api_id":       restAPIID,
		"flag_rest_api_id":  trust.SourceRESTAPIID,
		"flag_adapter_id":   trust.AdapterAPIID,
		"flag_proxy_api_id": trust.CallerProxyAPIID,
	}).Warn("MCP loop trust descriptor does not match an admitted paired proxy")
}

func (m *MCPLoopAuthBypassMiddleware) installLoopSession(r *http.Request, trust mcpAdapterLoopTrust) {
	session := user.NewSessionState()
	session.OrgID = m.Spec.OrgID
	session.KeyID = mcpLoopAuthSessionKey(trust)
	session.MetaData = map[string]interface{}{
		"mcp_adapter_api_id":      trust.AdapterAPIID,
		"mcp_caller_proxy_api_id": trust.CallerProxyAPIID,
		"mcp_source_rest_api_id":  trust.SourceRESTAPIID,
	}
	ctxSetMCPAdapterLoopSession(r, session, gatewayHashKeys(m.Gw))
}

type MCPLoopAuthRestoreMiddleware struct {
	*BaseMiddleware
}

func (m *MCPLoopAuthRestoreMiddleware) Name() string {
	return "MCPLoopAuthRestoreMiddleware"
}

func (m *MCPLoopAuthRestoreMiddleware) EnabledForSpec() bool {
	return mcpLoopAuthEnabledForSpec(m.Spec)
}

//nolint:staticcheck // ST1008: middleware interface requires (error, int).
func (m *MCPLoopAuthRestoreMiddleware) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxMCPAdapterLoopAuthBypassed(r) && ctxGetRequestStatus(r) == StatusOkAndIgnore {
		ctxSetRequestStatus(r, StatusOk)
	}
	ctxSetMCPAdapterLoopAuthBypassed(r, false)
	return nil, http.StatusOK
}

func mcpLoopAuthEnabledForSpec(spec *APISpec) bool {
	if spec == nil || spec.APIDefinition == nil {
		return false
	}
	return !spec.IsMCPManaged() && !spec.IsSyntheticMCPAdapter()
}

func mcpLoopAuthSessionKey(trust mcpAdapterLoopTrust) string {
	return fmt.Sprintf("mcp-loop:%s:%s", trust.AdapterAPIID, trust.CallerProxyAPIID)
}

var errMCPLoopTrustMismatch = errors.New("MCP loop trust descriptor does not match an admitted paired proxy")

func ctxSetMCPAdapterLoopSession(r *http.Request, session *user.SessionState, hashKeys bool) {
	if session.KeyID == "" {
		session.KeyID = ctx.GetAuthToken(r)
	}
	if session.KeyHashEmpty() {
		session.SetKeyHash(storage.HashKey(session.KeyID, hashKeys))
	}

	reqCtx := r.Context()
	reqCtx = context.WithValue(reqCtx, ctx.SessionData, session)
	reqCtx = context.WithValue(reqCtx, ctx.AuthToken, session.KeyID)
	setContext(r, reqCtx)
}

func gatewayHashKeys(gw *Gateway) bool {
	if gw == nil {
		return false
	}
	value := gw.config.Load()
	if value == nil {
		return false
	}
	cfg, ok := value.(config.Config)
	return ok && cfg.HashKeys
}
