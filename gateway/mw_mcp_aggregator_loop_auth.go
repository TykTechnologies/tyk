package gateway

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/user"
)

const (
	mcpAggregatorLoopTrustKey  mcpContextKey = "mcp_aggregator_loop_trust"
	mcpAggregatorLoopBypassKey mcpContextKey = "mcp_aggregator_loop_bypass"

	mcpAggregatorLoopSessionMetaKey = "mcp_aggregator_api_id"
)

// mcpAggregatorLoopTrust marks an in-process call from an aggregator to one of
// its aggregated MCP proxies. The aggregator has already authenticated the
// caller, so the aggregated proxy's own client authentication is skipped.
type mcpAggregatorLoopTrust struct {
	OrgID           string
	AggregatorAPIID string
	UpstreamAPIID   string
}

var errMCPAggregatorLoopTrustMismatch = errors.New("MCP aggregator loop trust descriptor does not match an admitted aggregated MCP proxy")

func ctxSetMCPAggregatorLoopTrust(r *http.Request, trust *mcpAggregatorLoopTrust) {
	setCtxValue(r, mcpAggregatorLoopTrustKey, trust)
}

func ctxGetMCPAggregatorLoopTrust(r *http.Request) (*mcpAggregatorLoopTrust, bool) {
	trust, ok := r.Context().Value(mcpAggregatorLoopTrustKey).(*mcpAggregatorLoopTrust)
	return trust, ok && trust != nil
}

func isMCPAggregatorLoopRequest(r *http.Request) bool {
	_, ok := ctxGetMCPAggregatorLoopTrust(r)
	return ok
}

func ctxMCPAggregatorLoopAuthBypassed(r *http.Request) bool {
	bypassed, _ := r.Context().Value(mcpAggregatorLoopBypassKey).(bool)
	return bypassed
}

func mcpAggregatorLoopAuthEnabledForSpec(spec *APISpec) bool {
	return spec != nil && spec.APIDefinition != nil && spec.IsMCPManaged() && !spec.IsMCPAggregator() && !spec.IsSyntheticMCPAdapter()
}

// MCPAggregatorLoopAuthBypassMiddleware admits trusted in-process calls from an
// MCP aggregator into one of its aggregated MCP proxies.
type MCPAggregatorLoopAuthBypassMiddleware struct {
	*BaseMiddleware
}

func (m *MCPAggregatorLoopAuthBypassMiddleware) Name() string {
	return "MCPAggregatorLoopAuthBypassMiddleware"
}

func (m *MCPAggregatorLoopAuthBypassMiddleware) EnabledForSpec() bool {
	return mcpAggregatorLoopAuthEnabledForSpec(m.Spec)
}

//nolint:staticcheck // ST1008: middleware interface requires (error, int).
func (m *MCPAggregatorLoopAuthBypassMiddleware) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	trust, ok := ctxGetMCPAggregatorLoopTrust(r)
	if !ok {
		return nil, http.StatusOK
	}
	// The trust applies to this hop only; a further loop must authenticate.
	ctxSetMCPAggregatorLoopTrust(r, nil)

	if !m.validLoopTrust(trust) {
		m.Logger().WithFields(map[string]interface{}{
			"api_id":            m.Spec.APIID,
			"aggregator_api_id": trust.AggregatorAPIID,
			"upstream_api_id":   trust.UpstreamAPIID,
		}).Warn(errMCPAggregatorLoopTrustMismatch.Error())
		return errMCPAggregatorLoopTrustMismatch, http.StatusForbidden
	}

	session := user.NewSessionState()
	session.OrgID = m.Spec.OrgID
	session.KeyID = fmt.Sprintf("mcp-aggregator:%s:%s", trust.AggregatorAPIID, trust.UpstreamAPIID)
	// Scoped to the admitted aggregated proxy, so the session grants nothing
	// on any other API it might reach.
	session.AccessRights = map[string]user.AccessDefinition{
		m.Spec.APIID: {APIID: m.Spec.APIID, APIName: m.Spec.Name},
	}
	session.MetaData = map[string]interface{}{
		mcpAggregatorLoopSessionMetaKey: trust.AggregatorAPIID,
		"mcp_upstream_api_id":           trust.UpstreamAPIID,
	}
	ctxSetMCPAdapterLoopSession(r, session, gatewayHashKeys(m.Gw))
	setCtxValue(r, mcpAggregatorLoopBypassKey, true)
	ctxSetRequestStatus(r, StatusOkAndIgnore)
	return nil, http.StatusOK
}

func (m *MCPAggregatorLoopAuthBypassMiddleware) validLoopTrust(trust *mcpAggregatorLoopTrust) bool {
	if m.Gw == nil || trust.UpstreamAPIID != m.Spec.APIID || trust.OrgID != m.Spec.OrgID {
		return false
	}
	agg, ok := m.Gw.mcpAggregatorIndex.Lookup(trust.AggregatorAPIID)
	return ok && agg.OrgID == trust.OrgID && m.Gw.mcpAggregatorIndex.Allows(trust.AggregatorAPIID, trust.UpstreamAPIID)
}

// MCPAggregatorLoopAuthRestoreMiddleware ends the authentication skip started
// by MCPAggregatorLoopAuthBypassMiddleware.
type MCPAggregatorLoopAuthRestoreMiddleware struct {
	*BaseMiddleware
}

func (m *MCPAggregatorLoopAuthRestoreMiddleware) Name() string {
	return "MCPAggregatorLoopAuthRestoreMiddleware"
}

func (m *MCPAggregatorLoopAuthRestoreMiddleware) EnabledForSpec() bool {
	return mcpAggregatorLoopAuthEnabledForSpec(m.Spec)
}

//nolint:staticcheck // ST1008: middleware interface requires (error, int).
func (m *MCPAggregatorLoopAuthRestoreMiddleware) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		ctxSetRequestStatus(r, StatusOk)
	}
	setCtxValue(r, mcpAggregatorLoopBypassKey, false)
	return nil, http.StatusOK
}

// endMCPAggregatorLoopSession drops an aggregator loop session before the
// aggregated proxy loops into another API, which must then authenticate the
// request on its own terms.
func endMCPAggregatorLoopSession(r *http.Request) {
	session := ctxGetSession(r)
	if session == nil || session.MetaData[mcpAggregatorLoopSessionMetaKey] == nil {
		return
	}
	setCtxValue(r, ctx.SessionData, (*user.SessionState)(nil))
	httpctx.SetSelfLooping(r, false)
}
