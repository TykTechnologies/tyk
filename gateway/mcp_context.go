package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"

	sdkAuth "github.com/modelcontextprotocol/go-sdk/auth"

	internalhttputil "github.com/TykTechnologies/tyk/internal/httputil"
	restmcpadapter "github.com/TykTechnologies/tyk/internal/mcp/adapter"
)

type mcpContextKey string

const (
	mcpAcceptedOriginKey       mcpContextKey = "mcp_accepted_origin"
	mcpOriginHopKey            mcpContextKey = "mcp_origin_hop"
	mcpAdapterCallerProxyIDKey mcpContextKey = "mcp_adapter_caller_proxy_id"
	mcpAdapterGatewayKey       mcpContextKey = "mcp_adapter_gateway"
	mcpAdapterSpecKey          mcpContextKey = "mcp_adapter_spec"
	mcpAdapterParentRequestKey mcpContextKey = "mcp_adapter_parent_request"
	mcpAdapterLoopTrustKey     mcpContextKey = "mcp_adapter_loop_trust"
	mcpAdapterLoopBypassKey    mcpContextKey = "mcp_adapter_loop_bypass"
)

type mcpAdapterLoopTrust struct {
	SourceRESTAPIID  string
	AdapterAPIID     string
	CallerProxyAPIID string
}

func ctxSetMCPAdapterCallerProxyID(r *http.Request, proxyAPIID string) {
	setCtxValue(r, mcpAdapterCallerProxyIDKey, proxyAPIID)
}

func ctxGetMCPAdapterCallerProxyID(r *http.Request) string {
	if v := r.Context().Value(mcpAdapterCallerProxyIDKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func ctxSetMCPAdapterLoopTrust(r *http.Request, trust mcpAdapterLoopTrust) {
	setCtxValue(r, mcpAdapterLoopTrustKey, trust)
}

func ctxGetMCPAdapterLoopTrust(r *http.Request) (mcpAdapterLoopTrust, bool) {
	if v := r.Context().Value(mcpAdapterLoopTrustKey); v != nil {
		if trust, ok := v.(mcpAdapterLoopTrust); ok {
			return trust, true
		}
	}
	return mcpAdapterLoopTrust{}, false
}

func ctxSetMCPAdapterLoopAuthBypassed(r *http.Request, bypassed bool) {
	setCtxValue(r, mcpAdapterLoopBypassKey, bypassed)
}

func ctxMCPAdapterLoopAuthBypassed(r *http.Request) bool {
	if v := r.Context().Value(mcpAdapterLoopBypassKey); v != nil {
		if bypassed, ok := v.(bool); ok {
			return bypassed
		}
	}
	return false
}

func installMCPAdapterCallContext(r *http.Request, gw *Gateway, spec *APISpec) {
	ctx := context.WithValue(r.Context(), mcpAdapterGatewayKey, gw)
	ctx = context.WithValue(ctx, mcpAdapterSpecKey, spec)
	ctx = context.WithValue(ctx, mcpAdapterParentRequestKey, r)
	*r = *r.WithContext(ctx)
}

func mcpAdapterGatewayFromContext(ctx context.Context) *Gateway {
	if v := ctx.Value(mcpAdapterGatewayKey); v != nil {
		if gw, ok := v.(*Gateway); ok {
			return gw
		}
	}
	return nil
}

func mcpAdapterSpecFromContext(ctx context.Context) *APISpec {
	if v := ctx.Value(mcpAdapterSpecKey); v != nil {
		if spec, ok := v.(*APISpec); ok {
			return spec
		}
	}
	return nil
}

func mcpAdapterParentRequestFromContext(ctx context.Context) *http.Request {
	if v := ctx.Value(mcpAdapterParentRequestKey); v != nil {
		if req, ok := v.(*http.Request); ok {
			return req
		}
	}
	return nil
}

// The public decision and internal hop are separate immutable values: accepting
// one proxy's Origin must never authorize another caller of a shared adapter.
type mcpAcceptedOrigin struct {
	ProxyAPIID string
	Origin     string // Empty only when the public request had no Origin header.
}

type mcpOriginHop struct {
	Decision        mcpAcceptedOrigin
	AdapterAPIID    string
	SourceRESTAPIID string
	Owner           string
}

func acceptMCPOrigin(r *http.Request, spec *APISpec, origin string) {
	if spec != nil && spec.IsPairedMCPAdapterProxy() {
		setCtxValue(r, mcpAcceptedOriginKey, mcpAcceptedOrigin{spec.APIID, origin})
	}
}

func establishMCPAdapterOriginHop(r *http.Request, gw *Gateway, caller, target *APISpec) bool {
	// Clear any proof from an earlier hop before examining this caller.
	setCtxValue(r, mcpOriginHopKey, mcpOriginHop{})
	decision, ok := r.Context().Value(mcpAcceptedOriginKey).(mcpAcceptedOrigin)
	if !ok || decision.ProxyAPIID != caller.APIID || target == nil || !target.IsSyntheticMCPAdapter() {
		return false
	}
	_, sourceID, paired := pairedMCPAdapterTarget(caller.Proxy.TargetURL)
	if !paired || sourceID != target.MCPAdapter.SourceRESTAPIID {
		return false
	}
	owner, err := mcpAdapterSessionOwner(r, caller)
	if err != nil {
		return false
	}
	hop := mcpOriginHop{decision, target.APIID, sourceID, owner}
	setCtxValue(r, mcpOriginHopKey, hop)
	if !validMCPAdapterOriginHop(r, gw, target) {
		setCtxValue(r, mcpOriginHopKey, mcpOriginHop{})
		return false
	}
	ctxSetMCPAdapterCallerProxyID(r, caller.APIID)
	return true
}

func validMCPAdapterOriginHop(r *http.Request, gw *Gateway, target *APISpec) bool {
	if gw == nil || target == nil || !target.IsSyntheticMCPAdapter() {
		return false
	}
	hop, ok := r.Context().Value(mcpOriginHopKey).(mcpOriginHop)
	if !ok || hop.Owner == "" || hop.Decision.ProxyAPIID == "" || hop.AdapterAPIID != target.APIID || hop.SourceRESTAPIID != target.MCPAdapter.SourceRESTAPIID {
		return false
	}
	// Use one immutable snapshot, so a reload cannot mix two pairing decisions.
	snapshot := gw.mcpPairingIndex.Snapshot()
	source, ok := snapshot.LookupAdapter(hop.AdapterAPIID)
	if !ok || source.SourceRESTAPIID != hop.SourceRESTAPIID || !snapshot.AllowsCaller(hop.AdapterAPIID, hop.Decision.ProxyAPIID) {
		return false
	}
	origins := r.Header.Values("Origin")
	if hop.Decision.Origin == "" {
		return len(origins) == 0
	}
	if len(origins) != 1 {
		return false
	}
	origin, err := internalhttputil.CanonicalOrigin(origins[0])
	return err == nil && origin == hop.Decision.Origin
}

func mcpAdapterSessionOwner(r *http.Request, caller *APISpec) (string, error) {
	kind, principal := "anonymous", ""
	if !caller.UseKeylessAccess {
		kind = "authenticated"
		session := ctxGetSession(r)
		if session == nil || session.KeyID == "" {
			return "", fmt.Errorf("authenticated MCP principal is missing")
		}
		principal = session.KeyID
	}
	sdkIdentity := ""
	if info := sdkAuth.TokenInfoFromContext(r.Context()); info != nil {
		sdkIdentity = info.UserID
	}
	tuple, err := json.Marshal([]string{"tyk-mcp-session-owner-v1", caller.OrgID, caller.APIID, kind, principal, sdkIdentity})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(tuple)), nil
}

func installMCPAdapterRequestBinding(r *http.Request, gw *Gateway, spec *APISpec) bool {
	if !validMCPAdapterOriginHop(r, gw, spec) {
		return false
	}
	hop := r.Context().Value(mcpOriginHopKey).(mcpOriginHop)
	// Freeze the current parent headers/URL before the SDK keeps this message.
	parent := r.Clone(r.Context())
	installMCPAdapterCallContext(parent, gw, spec)
	*r = *r.WithContext(restmcpadapter.WithRequestBinding(r.Context(), parent.Context(), hop.Owner))
	return true
}
