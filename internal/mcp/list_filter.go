package mcp

import (
	"encoding/json"
	"slices"

	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/user"
)

// FilterDiscoveryBody intersects an upstream server/discover result with the
// Gateway's routable versions and filters known capabilities using JSON-RPC
// method rules. Unknown result, capability, metadata, and extension fields are
// retained byte-for-byte until an actual edit requires re-encoding.
//
// credentialSpecific is true only when credential rules removed a capability
// that global rules would have retained. Only that case receives private,
// zero-TTL cache hints.
func FilterDiscoveryBody(body []byte, globalRules, credentialRules []user.AccessControlRules) (filtered []byte, changed, credentialSpecific bool) {
	var envelope JSONRPCResponse
	if json.Unmarshal(body, &envelope) != nil || envelope.Result == nil {
		return nil, false, false
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(envelope.Result, &result) != nil {
		return nil, false, false
	}

	if versionsRaw, present := result["supportedVersions"]; present {
		var upstream []string
		if json.Unmarshal(versionsRaw, &upstream) == nil {
			upstreamSet := make(map[string]struct{}, len(upstream))
			for _, version := range upstream {
				upstreamSet[version] = struct{}{}
			}
			versions := make([]string, 0, len(servedProtocolVersions))
			for _, served := range servedProtocolVersions {
				if _, supported := upstreamSet[served]; supported {
					versions = append(versions, served)
				}
			}
			if !slices.Equal(versions, upstream) {
				result["supportedVersions"], _ = json.Marshal(versions)
				changed = true
			}
		}
	}

	if capabilitiesRaw, present := result["capabilities"]; present {
		var capabilities map[string]json.RawMessage
		if json.Unmarshal(capabilitiesRaw, &capabilities) == nil {
			capabilitiesChanged := false
			for capability, methods := range InitializeCapabilityMethods {
				if _, advertised := capabilities[capability]; !advertised {
					continue
				}
				globalDenied := AnyMethodDenied(globalRules, methods)
				credentialDenied := AnyMethodDenied(credentialRules, methods)
				if !globalDenied && !credentialDenied {
					continue
				}
				delete(capabilities, capability)
				capabilitiesChanged = true
				credentialSpecific = credentialSpecific || (!globalDenied && credentialDenied)
			}
			if capabilitiesChanged {
				result["capabilities"], _ = json.Marshal(capabilities)
				changed = true
			}
		}
	}

	if !changed {
		return nil, false, false
	}
	if credentialSpecific {
		SetPrivateCacheHints(result)
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, false, false
	}
	envelope.Result = resultBytes
	filtered, err = json.Marshal(&envelope)
	if err != nil {
		return nil, false, false
	}
	return filtered, true, credentialSpecific
}

// ListFilterConfig holds the configuration for filtering a specific list method.
type ListFilterConfig struct {
	ArrayKey  string                                                    // JSON key of the array in result (e.g. "tools")
	NameField string                                                    // JSON field to match against rules (e.g. "name", "uri")
	RulesFrom func(rights user.MCPAccessRights) user.AccessControlRules // extracts the relevant rules
}

// ListFilterConfigs maps array keys to their filter configurations.
// Both method-based lookup and result-key-based lookup (InferListConfigFromResult)
// reference these shared definitions.
var ListFilterConfigs = map[string]*ListFilterConfig{
	"tools": {
		ArrayKey:  "tools",
		NameField: "name",
		RulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Tools },
	},
	"prompts": {
		ArrayKey:  "prompts",
		NameField: "name",
		RulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Prompts },
	},
	"resources": {
		ArrayKey:  "resources",
		NameField: "uri",
		RulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Resources },
	},
	"resourceTemplates": {
		ArrayKey:  "resourceTemplates",
		NameField: "uriTemplate",
		RulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Resources },
	},
}

// JSONRPCResponse represents a JSON-RPC 2.0 response envelope.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// ExtractStringField extracts a string field from a JSON object.
// Returns empty string if the field doesn't exist or isn't a string.
func ExtractStringField(raw json.RawMessage, field string) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}

	val, ok := obj[field]
	if !ok {
		return ""
	}

	var s string
	if err := json.Unmarshal(val, &s); err != nil {
		return ""
	}

	return s
}

// FilterItems applies access control rules to a slice of JSON items, returning
// only items that are permitted. Items whose name field cannot be extracted are
// included (fail-open for malformed data).
func FilterItems(items []json.RawMessage, nameField string, rules user.AccessControlRules) []json.RawMessage {
	return FilterItemsWithRuleSets(items, nameField, []user.AccessControlRules{rules})
}

// FilterItemsWithRuleSets applies multiple access-control rule sets to a slice
// of JSON items. An item is included only when every non-empty rule set permits
// it. This composes allow lists as an intersection and block lists as a union.
func FilterItemsWithRuleSets(items []json.RawMessage, nameField string, ruleSets []user.AccessControlRules) []json.RawMessage {
	filtered := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		name := ExtractStringField(item, nameField)
		if name == "" {
			// Can't extract the field — include the item (fail open for malformed data).
			filtered = append(filtered, item)
			continue
		}

		if !CheckAccessControlRuleSets(ruleSets, name) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

// ReencodeEnvelope marshals the filtered items back into the JSON-RPC response
// envelope, performing the three-step re-marshal: items -> result -> envelope.
func ReencodeEnvelope(envelope *JSONRPCResponse, result map[string]json.RawMessage, arrayKey string, filtered []json.RawMessage) ([]byte, error) {
	filteredBytes, err := json.Marshal(filtered)
	if err != nil {
		return nil, err
	}

	result[arrayKey] = filteredBytes

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	envelope.Result = resultBytes

	return json.Marshal(envelope)
}

// FilterJSONRPCBody parses a JSON-RPC response body, filters the list items
// according to the given config and rules, and returns the re-encoded body only
// when at least one item was removed. Returns (nil, false) for parse failures or
// unchanged content, signalling that the caller must retain the original bytes.
func FilterJSONRPCBody(body []byte, cfg *ListFilterConfig, rules user.AccessControlRules) ([]byte, bool) {
	return FilterJSONRPCBodyWithRuleSets(body, cfg, []user.AccessControlRules{rules})
}

// FilterJSONRPCBodyWithRuleSets parses a JSON-RPC response body, filters the
// list items according to the given config and rule sets, and returns the
// re-encoded body.
func FilterJSONRPCBodyWithRuleSets(body []byte, cfg *ListFilterConfig, ruleSets []user.AccessControlRules) ([]byte, bool) {
	var envelope JSONRPCResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false
	}

	if envelope.Result == nil {
		return nil, false
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return nil, false
	}

	return FilterParsedJSONRPCWithRuleSets(&envelope, result, cfg, ruleSets)
}

// FilterParsedJSONRPC filters items in an already-parsed JSON-RPC result and
// re-encodes the envelope. Returns (nil, false) when the array key is missing,
// items cannot be parsed, no items were removed, or re-encoding fails.
func FilterParsedJSONRPC(envelope *JSONRPCResponse, result map[string]json.RawMessage, cfg *ListFilterConfig, rules user.AccessControlRules) ([]byte, bool) {
	return FilterParsedJSONRPCWithRuleSets(envelope, result, cfg, []user.AccessControlRules{rules})
}

// FilterParsedJSONRPCWithRuleSets filters items in an already-parsed JSON-RPC
// result using multiple rule sets and re-encodes the envelope.
func FilterParsedJSONRPCWithRuleSets(envelope *JSONRPCResponse, result map[string]json.RawMessage, cfg *ListFilterConfig, ruleSets []user.AccessControlRules) ([]byte, bool) {
	itemsRaw, exists := result[cfg.ArrayKey]
	if !exists {
		return nil, false
	}

	var items []json.RawMessage
	if err := json.Unmarshal(itemsRaw, &items); err != nil {
		return nil, false
	}

	filtered := FilterItemsWithRuleSets(items, cfg.NameField, ruleSets)
	if len(filtered) == len(items) {
		return nil, false
	}

	SetPrivateCacheHints(result)

	newBody, err := ReencodeEnvelope(envelope, result, cfg.ArrayKey, filtered)
	if err != nil {
		return nil, false
	}

	return newBody, true
}

// SetPrivateCacheHints prevents an authorization-specific MCP result from
// being reused for a different caller. It operates on the raw result map so
// unknown fields and pagination cursors are preserved when the envelope is
// re-encoded.
func SetPrivateCacheHints(result map[string]json.RawMessage) {
	result["cacheScope"] = json.RawMessage(`"private"`)
	result["ttlMs"] = json.RawMessage(`0`)
}

// InferListConfigFromResult determines the list type by inspecting which
// well-known array key is present in the JSON-RPC result object.
func InferListConfigFromResult(result map[string]json.RawMessage) *ListFilterConfig {
	// Check resourceTemplates before resources — "resources" would also match
	// if we checked it first, since both use the Resources access rights,
	// but we need the correct arrayKey and nameField.
	lookupOrder := []string{"tools", "prompts", "resourceTemplates", "resources"}
	for _, key := range lookupOrder {
		if _, ok := result[key]; ok {
			return ListFilterConfigs[key]
		}
	}
	return nil
}

// InitializeCapabilityMethods maps initialize response capability keys to the
// JSON-RPC methods that make the capability usable.
var InitializeCapabilityMethods = map[string][]string{
	"tools":     {MethodToolsList, MethodToolsCall},
	"resources": {MethodResourcesList, MethodResourcesTemplatesList, MethodResourcesRead},
	"prompts":   {MethodPromptsList, MethodPromptsGet},
	"sampling":  {MethodSamplingCreateMessage},
}

// FilterInitializeCapabilitiesBody removes initialize response capabilities
// whose backing JSON-RPC methods are denied by any rule set.
func FilterInitializeCapabilitiesBody(body []byte, ruleSets []user.AccessControlRules) ([]byte, bool) {
	var envelope JSONRPCResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false
	}

	if envelope.Result == nil {
		return nil, false
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return nil, false
	}

	return FilterInitializeCapabilitiesParsed(&envelope, result, ruleSets)
}

// FilterInitializeCapabilitiesParsed removes denied capabilities in an
// already-parsed initialize result and re-encodes the response envelope.
func FilterInitializeCapabilitiesParsed(envelope *JSONRPCResponse, result map[string]json.RawMessage, ruleSets []user.AccessControlRules) ([]byte, bool) {
	capabilitiesRaw, exists := result["capabilities"]
	if !exists {
		return nil, false
	}

	var capabilities map[string]json.RawMessage
	if err := json.Unmarshal(capabilitiesRaw, &capabilities); err != nil {
		return nil, false
	}

	changed := false
	for capability, methods := range InitializeCapabilityMethods {
		if _, exists := capabilities[capability]; !exists {
			continue
		}

		if AnyMethodDenied(ruleSets, methods) {
			delete(capabilities, capability)
			changed = true
		}
	}

	if !changed {
		return nil, false
	}
	SetPrivateCacheHints(result)

	capabilitiesBytes, err := json.Marshal(capabilities)
	if err != nil {
		return nil, false
	}
	result["capabilities"] = capabilitiesBytes

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, false
	}
	envelope.Result = resultBytes

	newBody, err := json.Marshal(envelope)
	if err != nil {
		return nil, false
	}
	return newBody, true
}

// AnyMethodDenied returns true when any of the provided methods is denied by
// any non-empty rule set.
func AnyMethodDenied(ruleSets []user.AccessControlRules, methods []string) bool {
	for _, method := range methods {
		if CheckAccessControlRuleSets(ruleSets, method) {
			return true
		}
	}
	return false
}

// CheckAccessControlRuleSets evaluates multiple allow/block rule sets against
// a name. It returns true if any non-empty rule set denies the name.
func CheckAccessControlRuleSets(ruleSets []user.AccessControlRules, name string) bool {
	for _, rules := range ruleSets {
		if rules.IsEmpty() {
			continue
		}
		if CheckAccessControlRules(rules, name) {
			return true
		}
	}
	return false
}

// CheckAccessControlRules evaluates allow/block lists against a name.
// Returns true if the name is denied, false if permitted.
//
// Evaluation order:
//  1. Blocked is checked first — if matched, the request is denied.
//  2. If Allowed is non-empty and the name does not match any entry, the request is denied.
//  3. If both lists are empty, access is permitted.
func CheckAccessControlRules(rules user.AccessControlRules, name string) bool {
	for _, pattern := range rules.Blocked {
		if matchPattern(pattern, name) {
			return true
		}
	}

	if len(rules.Allowed) == 0 {
		return false
	}

	for _, pattern := range rules.Allowed {
		if matchPattern(pattern, name) {
			return false
		}
	}

	return true
}

// matchPattern tests name against a regex pattern anchored with ^...$, enforcing full-match semantics.
// Uses the tyk/regexp package which caches compiled patterns.
// Falls back to exact-string comparison if the pattern is not valid regex.
func matchPattern(pattern, name string) bool {
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	if err != nil {
		return pattern == name
	}
	return re.MatchString(name)
}
