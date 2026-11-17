package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/user"
)

// FilterDiscoveryBody intersects an upstream server/discover result with the
// Gateway's routable versions and filters known capabilities using JSON-RPC
// method rules. Unknown result, capability, metadata, and extension fields are
// retained byte-for-byte until an actual edit requires re-encoding.
//
// Applicable credential method rules make every discovery result private,
// including results whose advertised capabilities already satisfy the rules.
func FilterDiscoveryBody(body []byte, globalRules, credentialRules []user.AccessControlRules, endpoints ...ProtocolSupport) (filtered []byte, changed, credentialSpecific bool, invalid error) {
	envelope, err := decodeOwnedJSONObject(body, "JSON-RPC response", map[string]struct{}{
		"jsonrpc": {}, "id": {}, "method": {}, "result": {}, "error": {},
	})
	if err != nil {
		return nil, false, false, err
	}
	var version string
	if raw, ok := envelope["jsonrpc"]; !ok || json.Unmarshal(raw, &version) != nil || version != "2.0" {
		return nil, false, false, invalidDiscovery("missing or invalid jsonrpc version")
	}
	if raw, ok := envelope["id"]; !ok || !validJSONRPCResponseID(raw) {
		return nil, false, false, invalidDiscovery("missing or invalid response id")
	}
	if _, present := envelope["method"]; present {
		return nil, false, false, invalidDiscovery("response must not contain a method")
	}
	resultRaw, hasResult := envelope["result"]
	errorRaw, hasError := envelope["error"]
	if hasResult == hasError {
		return nil, false, false, invalidDiscovery("response must contain exactly one of result or error")
	}
	credentialSpecific = hasFilterRules(credentialRules)
	if hasError {
		errorFields, err := decodeOwnedJSONObject(errorRaw, "JSON-RPC error", map[string]struct{}{"code": {}, "message": {}, "data": {}})
		if err != nil {
			return nil, false, false, err
		}
		var code json.Number
		codeDecoder := json.NewDecoder(bytes.NewReader(errorFields["code"]))
		codeDecoder.UseNumber()
		if codeDecoder.Decode(&code) != nil {
			return nil, false, false, invalidDiscovery("missing or invalid JSON-RPC error code")
		}
		if _, err := code.Int64(); err != nil {
			return nil, false, false, invalidDiscovery("JSON-RPC error code must be an integer")
		}
		var message string
		if json.Unmarshal(errorFields["message"], &message) != nil {
			return nil, false, false, invalidDiscovery("missing or invalid JSON-RPC error message")
		}
		return nil, false, credentialSpecific, nil
	}
	result, err := decodeOwnedJSONObject(resultRaw, "discovery result", map[string]struct{}{
		"supportedVersions": {}, "capabilities": {},
	})
	if err != nil {
		return nil, false, false, err
	}
	versionsRaw, present := result["supportedVersions"]
	if !present {
		return nil, false, false, invalidDiscovery("missing supportedVersions")
	}
	var upstream []string
	if json.Unmarshal(versionsRaw, &upstream) != nil || upstream == nil {
		return nil, false, false, invalidDiscovery("supportedVersions must be a non-null string array")
	}
	capabilitiesRaw, present := result["capabilities"]
	if !present {
		return nil, false, false, invalidDiscovery("missing capabilities")
	}
	ownedCapabilities := make(map[string]struct{}, len(InitializeCapabilityMethods))
	for capability := range InitializeCapabilityMethods {
		ownedCapabilities[capability] = struct{}{}
	}
	capabilities, err := decodeOwnedJSONObject(capabilitiesRaw, "discovery capabilities", ownedCapabilities)
	if err != nil {
		return nil, false, false, err
	}

	versionsSupported := ServedProtocolVersions()
	if len(endpoints) > 0 && endpoints[0] != nil {
		versionsSupported = endpoints[0].SupportedProtocolVersions()
	}
	upstreamSet := make(map[string]struct{}, len(upstream))
	for _, version := range upstream {
		upstreamSet[version] = struct{}{}
	}
	versions := make([]string, 0, len(versionsSupported))
	for _, served := range versionsSupported {
		if _, supported := upstreamSet[served]; supported {
			versions = append(versions, served)
		}
	}
	if !slices.Equal(versions, upstream) {
		encodedVersions, err := json.Marshal(versions)
		if err != nil {
			return nil, false, false, invalidDiscovery("encode filtered versions")
		}
		result["supportedVersions"] = encodedVersions
		changed = true
	}

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
		encodedCapabilities, err := json.Marshal(capabilities)
		if err != nil {
			return nil, false, false, invalidDiscovery("encode filtered capabilities")
		}
		result["capabilities"] = encodedCapabilities
		changed = true
	}

	if !changed && !credentialSpecific {
		return nil, false, false, nil
	}
	if credentialSpecific {
		SetPrivateCacheHints(result)
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, false, false, invalidDiscovery("encode discovery result")
	}
	envelope["result"] = resultBytes
	filtered, err = json.Marshal(envelope)
	if err != nil {
		return nil, false, false, invalidDiscovery("encode discovery response")
	}
	return filtered, true, credentialSpecific, nil
}

// InvalidDiscoveryError reports an upstream discovery response that cannot be
// safely interpreted for policy and version enforcement.
type InvalidDiscoveryError struct{ Reason string }

func (e *InvalidDiscoveryError) Error() string { return "invalid MCP discovery response: " + e.Reason }

func invalidDiscovery(reason string) error { return &InvalidDiscoveryError{Reason: reason} }

func IsInvalidDiscoveryError(err error) bool {
	var target *InvalidDiscoveryError
	return errors.As(err, &target)
}

func validJSONRPCResponseID(raw json.RawMessage) bool {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return true
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return false
	}
	switch value.(type) {
	case string, json.Number:
		return true
	default:
		return false
	}
}

// JSONRPCResponseIDMatches compares a response ID with the trusted request ID
// without converting numeric identities through float64.
func JSONRPCResponseIDMatches(body []byte, expected any) bool {
	present, matches, err := JSONRPCResponseIDStatus(body, expected)
	return err == nil && present && matches
}

// JSONRPCResponseIDStatus reports whether an exact, valid response ID is
// present and matches the trusted request ID.
func JSONRPCResponseIDStatus(body []byte, expected any) (present, matches bool, err error) {
	fields, err := decodeOwnedJSONObject(body, "JSON-RPC response", map[string]struct{}{"id": {}})
	if err != nil {
		return false, false, err
	}
	raw, ok := fields["id"]
	if !ok {
		return false, false, nil
	}
	if !validJSONRPCResponseID(raw) {
		return true, false, invalidDiscovery("invalid response id")
	}
	var actual any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&actual) != nil {
		return true, false, invalidDiscovery("invalid response id")
	}
	switch actualValue := actual.(type) {
	case nil:
		return true, expected == nil, nil
	case string:
		expectedValue, ok := expected.(string)
		return true, ok && actualValue == expectedValue, nil
	case json.Number:
		expectedBytes, err := json.Marshal(expected)
		return true, err == nil && string(bytes.TrimSpace(expectedBytes)) == actualValue.String(), nil
	default:
		return true, false, invalidDiscovery("invalid response id")
	}
}

// ValidateJSONRPCServerMessage validates an unrelated server request or
// notification while a discovery response is pending.
func ValidateJSONRPCServerMessage(body []byte) error {
	fields, err := decodeOwnedJSONObject(body, "JSON-RPC server message", map[string]struct{}{
		"jsonrpc": {}, "id": {}, "method": {}, "params": {}, "result": {}, "error": {},
	})
	if err != nil {
		return err
	}
	var version, method string
	if json.Unmarshal(fields["jsonrpc"], &version) != nil || version != "2.0" {
		return invalidDiscovery("missing or invalid server message jsonrpc version")
	}
	if json.Unmarshal(fields["method"], &method) != nil || method == "" {
		return invalidDiscovery("missing or invalid server message method")
	}
	if _, present := fields["result"]; present {
		return invalidDiscovery("server message must not contain a result")
	}
	if _, present := fields["error"]; present {
		return invalidDiscovery("server message must not contain an error")
	}
	if raw, present := fields["id"]; present && !validJSONRPCResponseID(raw) {
		return invalidDiscovery("invalid server message id")
	}
	return nil
}

func decodeOwnedJSONObject(raw []byte, label string, owned map[string]struct{}) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return nil, invalidDiscovery("malformed " + label)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return nil, invalidDiscovery(label + " must be a non-null object")
	}
	fields := make(map[string]json.RawMessage)
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, invalidDiscovery("malformed " + label)
		}
		key := keyToken.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, invalidDiscovery("malformed " + label)
		}
		if _, relevant := owned[key]; relevant {
			if _, duplicate := seen[key]; duplicate {
				return nil, invalidDiscovery(fmt.Sprintf("duplicate %s field %q", label, key))
			}
			seen[key] = struct{}{}
		}
		fields[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, invalidDiscovery("malformed " + label)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, invalidDiscovery("multiple JSON values in " + label)
	}
	return fields, nil
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
	fields  map[string]json.RawMessage
}

// UnmarshalJSON retains unknown envelope fields and exact JSON-RPC identifiers.
func (r *JSONRPCResponse) UnmarshalJSON(data []byte) error {
	type response JSONRPCResponse
	var parsed response
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&parsed); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &parsed.fields); err != nil {
		return err
	}
	*r = JSONRPCResponse(parsed)
	return nil
}

// MarshalJSON changes only the result of a parsed response.
func (r JSONRPCResponse) MarshalJSON() ([]byte, error) {
	if r.fields == nil {
		type response JSONRPCResponse
		return json.Marshal(response(r))
	}
	fields := make(map[string]json.RawMessage, len(r.fields))
	for key, value := range r.fields {
		fields[key] = value
	}
	if r.Result != nil {
		fields["result"] = r.Result
	}
	return json.Marshal(fields)
}

func hasFilterRules(ruleSets []user.AccessControlRules) bool {
	for _, rules := range ruleSets {
		if !rules.IsEmpty() {
			return true
		}
	}
	return false
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
// according to the given config and rules, and returns the re-encoded body whenever applicable rules make it private, including unchanged pages.
// Returns (nil, false) for parse failures or absent rules, signalling that the caller must retain the original bytes.
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
// items cannot be parsed, no rules apply, or re-encoding fails.
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
	if !hasFilterRules(ruleSets) {
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

	if !changed && !hasFilterRules(ruleSets) {
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
