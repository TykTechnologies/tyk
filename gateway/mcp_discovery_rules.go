package gateway

import (
	"net/http"
	stdregexp "regexp"
	"strings"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

const oasJSONRPCMethodOperationPrefix = "json-rpc-method:"

func credentialSpecificMCPFilteringApplies(spec *APISpec, req *http.Request, ses *user.SessionState) bool {
	if spec == nil || req == nil || ses == nil || !spec.IsMCP() {
		return false
	}

	state := httpctx.GetJSONRPCRoutingState(req)
	if state == nil {
		return false
	}
	if cfg := listConfigForMCPMethod(state.Method); cfg != nil {
		return !sessionMCPRules(spec, ses, cfg).IsEmpty()
	}
	if state.Method == mcp.MethodInitialize {
		return !sessionJSONRPCMethodRules(spec, ses).IsEmpty()
	}
	if state.Method == mcp.MethodServerDiscover {
		return !sessionJSONRPCMethodRules(spec, ses).IsEmpty()
	}
	return false
}

func discoveryJSONRPCRuleSets(spec *APISpec, ses *user.SessionState) (global, credential []user.AccessControlRules) {
	if rules := oasJSONRPCMethodRules(spec); !rules.IsEmpty() {
		global = append(global, rules)
	}
	if rules := sessionJSONRPCMethodRules(spec, ses); !rules.IsEmpty() {
		credential = append(credential, rules)
	}
	return global, credential
}

func markMCPResponseEdited(req *http.Request) {
	if options := ctxGetCacheOptions(req); options != nil {
		options.responseEdited = true
	}
}

func effectiveMCPListRuleSets(spec *APISpec, ses *user.SessionState, cfg *mcp.ListFilterConfig) []user.AccessControlRules {
	ruleSets := make([]user.AccessControlRules, 0, 2)

	if rules := oasPrimitiveRules(spec, cfg); !rules.IsEmpty() {
		ruleSets = append(ruleSets, rules)
	}

	if rules := sessionMCPRules(spec, ses, cfg); !rules.IsEmpty() {
		ruleSets = append(ruleSets, rules)
	}

	return ruleSets
}

func effectiveJSONRPCMethodRuleSets(spec *APISpec, ses *user.SessionState) []user.AccessControlRules {
	ruleSets := make([]user.AccessControlRules, 0, 2)

	if rules := oasJSONRPCMethodRules(spec); !rules.IsEmpty() {
		ruleSets = append(ruleSets, rules)
	}

	if rules := sessionJSONRPCMethodRules(spec, ses); !rules.IsEmpty() {
		ruleSets = append(ruleSets, rules)
	}

	return ruleSets
}

func sessionMCPRules(spec *APISpec, ses *user.SessionState, cfg *mcp.ListFilterConfig) user.AccessControlRules {
	if spec == nil || ses == nil {
		return user.AccessControlRules{}
	}

	accessDef, ok := ses.AccessRights[spec.APIID]
	if !ok || accessDef.MCPAccessRights.IsEmpty() {
		return user.AccessControlRules{}
	}

	return cfg.RulesFrom(accessDef.MCPAccessRights)
}

func sessionJSONRPCMethodRules(spec *APISpec, ses *user.SessionState) user.AccessControlRules {
	if spec == nil || ses == nil {
		return user.AccessControlRules{}
	}

	accessDef, ok := ses.AccessRights[spec.APIID]
	if !ok || accessDef.JSONRPCMethodsAccessRights.IsEmpty() {
		return user.AccessControlRules{}
	}

	return accessDef.JSONRPCMethodsAccessRights
}

func oasPrimitiveRules(spec *APISpec, cfg *mcp.ListFilterConfig) user.AccessControlRules {
	middleware := oasMiddleware(spec)
	if middleware == nil {
		return user.AccessControlRules{}
	}

	switch cfg.ArrayKey {
	case "tools":
		return rulesFromOASMCPPrimitives(middleware.McpTools)
	case "prompts":
		return rulesFromOASMCPPrimitives(middleware.McpPrompts)
	case "resources", "resourceTemplates":
		return rulesFromOASMCPPrimitives(middleware.McpResources)
	default:
		return user.AccessControlRules{}
	}
}

func rulesFromOASMCPPrimitives(primitives oas.MCPPrimitives) user.AccessControlRules {
	var rules user.AccessControlRules
	for name, primitive := range primitives {
		if primitive == nil {
			continue
		}

		pattern := oasPrimitivePattern(name)
		if primitive.Block != nil && primitive.Block.Enabled {
			rules.Blocked = append(rules.Blocked, pattern)
		}
		if primitive.Allow != nil && primitive.Allow.Enabled {
			rules.Allowed = append(rules.Allowed, pattern)
		}
	}
	return rules
}

func oasPrimitivePattern(name string) string {
	if !strings.Contains(name, "*") {
		return stdregexp.QuoteMeta(name)
	}

	parts := strings.Split(name, "*")
	var pattern strings.Builder
	for i, part := range parts {
		if i > 0 {
			pattern.WriteString(".*")
		}
		pattern.WriteString(stdregexp.QuoteMeta(part))
	}
	return pattern.String()
}

func oasJSONRPCMethodRules(spec *APISpec) user.AccessControlRules {
	middleware := oasMiddleware(spec)
	if middleware == nil {
		return user.AccessControlRules{}
	}

	var rules user.AccessControlRules
	for operationID, operation := range middleware.Operations {
		if operation == nil {
			continue
		}

		method, ok := jsonRPCMethodFromOperationID(operationID)
		if !ok {
			continue
		}

		pattern := stdregexp.QuoteMeta(method)
		if operation.Block != nil && operation.Block.Enabled {
			rules.Blocked = append(rules.Blocked, pattern)
		}
		if operation.Allow != nil && operation.Allow.Enabled {
			rules.Allowed = append(rules.Allowed, pattern)
		}
	}
	return rules
}

func jsonRPCMethodFromOperationID(operationID string) (string, bool) {
	if strings.HasPrefix(operationID, oasJSONRPCMethodOperationPrefix) {
		return strings.TrimPrefix(operationID, oasJSONRPCMethodOperationPrefix), true
	}
	if strings.HasPrefix(operationID, jsonrpc.MethodVEMPrefix) {
		return strings.TrimPrefix(operationID, jsonrpc.MethodVEMPrefix), true
	}
	return "", false
}

func oasMiddleware(spec *APISpec) *oas.Middleware {
	if spec == nil {
		return nil
	}
	return spec.OAS.GetTykMiddleware()
}
