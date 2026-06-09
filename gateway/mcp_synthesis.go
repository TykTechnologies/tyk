package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

// NormalizeMCPEndpoints calls synthesizeMCPEndpoints on every AccessDefinition
// in the session's AccessRights map. Call this after ApplyPolicies returns and
// before the session is used for rate limiting.
//
// Synthesized entries are in-memory only — never persisted to Redis.
func NormalizeMCPEndpoints(session *user.SessionState) {
	for apiID, ad := range session.AccessRights {
		synthesizeMCPEndpoints(&ad)
		session.AccessRights[apiID] = ad
	}
}

// synthesizeMCPEndpoints appends VEM endpoint entries derived from json_rpc_methods
// and mcp_primitives to ad.Endpoints. No-op when neither field is set.
func synthesizeMCPEndpoints(ad *user.AccessDefinition) {
	if len(ad.JSONRPCMethods) == 0 && len(ad.MCPPrimitives) == 0 {
		return
	}
	ad.Endpoints = append(ad.Endpoints, jsonRPCMethodEndpoints(ad.JSONRPCMethods)...)
	ad.Endpoints = append(ad.Endpoints, primitiveEndpoints(ad.MCPPrimitives)...)
}

// jsonRPCMethodEndpoints converts JSONRPCMethodLimit entries into VEM Endpoint entries.
// Entries with no rate limit configured are skipped.
func jsonRPCMethodEndpoints(methods []user.JSONRPCMethodLimit) user.Endpoints {
	var endpoints user.Endpoints
	for _, m := range methods {
		if !hasRateLimit(m.Limit) {
			continue
		}
		endpoints = append(endpoints, user.Endpoint{
			Path:    jsonrpc.MethodVEMPrefix + m.Name,
			Methods: user.EndpointMethods{{Name: http.MethodPost, Limit: m.Limit}},
		})
	}
	return endpoints
}

// primitiveEndpoints converts MCPPrimitiveLimit entries into VEM Endpoint entries.
// Entries with an unknown primitive type or no rate limit configured are skipped.
func primitiveEndpoints(primitives []user.MCPPrimitiveLimit) user.Endpoints {
	var endpoints user.Endpoints
	for _, p := range primitives {
		if !hasRateLimit(p.Limit) {
			continue
		}
		prefix := vemPrefixForPrimitiveType(p.Type)
		if prefix == "" {
			continue
		}
		endpoints = append(endpoints, user.Endpoint{
			Path:    prefix + p.Name,
			Methods: user.EndpointMethods{{Name: http.MethodPost, Limit: p.Limit}},
		})
	}
	return endpoints
}

// hasRateLimit reports whether a rate limit is configured (non-zero duration).
func hasRateLimit(limit user.RateLimit) bool {
	return limit.Duration() != 0
}

func vemPrefixForPrimitiveType(primType string) string {
	switch primType {
	case mcp.PrimitiveTypeTool:
		return mcp.ToolPrefix
	case mcp.PrimitiveTypeResource:
		return mcp.ResourcePrefix
	case mcp.PrimitiveTypePrompt:
		return mcp.PromptPrefix
	default:
		return ""
	}
}
