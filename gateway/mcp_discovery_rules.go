package gateway

import (
	stdregexp "regexp"
	"strings"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

const oasJSONRPCMethodOperationPrefix = "json-rpc-method:"

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
		return rulesFromOASMCPPrimitives(middleware.McpTools, false)
	case "prompts":
		return rulesFromOASMCPPrimitives(middleware.McpPrompts, false)
	case "resources", "resourceTemplates":
		return rulesFromOASMCPPrimitives(middleware.McpResources, true)
	default:
		return user.AccessControlRules{}
	}
}

func rulesFromOASMCPPrimitives(primitives oas.MCPPrimitives, resourcePatterns bool) user.AccessControlRules {
	var rules user.AccessControlRules
	for name, primitive := range primitives {
		if primitive == nil {
			continue
		}

		pattern := oasPrimitivePattern(name, resourcePatterns)
		if primitive.Block != nil && primitive.Block.Enabled {
			rules.Blocked = append(rules.Blocked, pattern)
		}
		if primitive.Allow != nil && primitive.Allow.Enabled {
			rules.Allowed = append(rules.Allowed, pattern)
		}
	}
	return rules
}

func oasPrimitivePattern(name string, resourcePatterns bool) string {
	if resourcePatterns && strings.HasSuffix(name, "/*") {
		return stdregexp.QuoteMeta(strings.TrimSuffix(name, "*")) + ".*"
	}
	return stdregexp.QuoteMeta(name)
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
