package mcp

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/user"
)

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
	filtered := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		name := ExtractStringField(item, nameField)
		if name == "" {
			// Can't extract the field — include the item (fail open for malformed data).
			filtered = append(filtered, item)
			continue
		}

		// CheckAccessControlRules returns true if denied.
		if !CheckAccessControlRules(rules, name) {
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
// according to the given config and rules, and returns the re-encoded body.
// Returns (nil, false) when any parsing or marshalling step fails, signalling
// that the caller should pass through the original body unmodified.
func FilterJSONRPCBody(body []byte, cfg *ListFilterConfig, rules user.AccessControlRules) ([]byte, bool) {
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

	return FilterParsedJSONRPC(&envelope, result, cfg, rules)
}

// FilterParsedJSONRPC filters items in an already-parsed JSON-RPC result and
// re-encodes the envelope. Returns (nil, false) when the array key is missing,
// items cannot be parsed, or re-encoding fails.
func FilterParsedJSONRPC(envelope *JSONRPCResponse, result map[string]json.RawMessage, cfg *ListFilterConfig, rules user.AccessControlRules) ([]byte, bool) {
	itemsRaw, exists := result[cfg.ArrayKey]
	if !exists {
		return nil, false
	}

	var items []json.RawMessage
	if err := json.Unmarshal(itemsRaw, &items); err != nil {
		return nil, false
	}

	filtered := FilterItems(items, cfg.NameField, rules)

	newBody, err := ReencodeEnvelope(envelope, result, cfg.ArrayKey, filtered)
	if err != nil {
		return nil, false
	}

	return newBody, true
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
