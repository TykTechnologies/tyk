package gateway

import (
	"context"
	"net/http"
)

type mcpContextKey string

const (
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
