package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

// MCPListFilterResponseHandler filters MCP list responses (tools/list, prompts/list,
// resources/list, resources/templates/list) to show only primitives the consumer
// is authorized to see based on their MCPAccessRights allow/block lists.
type MCPListFilterResponseHandler struct {
	BaseTykResponseHandler
}

// Base returns the base handler for middleware decoration.
func (h *MCPListFilterResponseHandler) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

// Name returns the handler name for logging and debugging.
func (h *MCPListFilterResponseHandler) Name() string {
	return "MCPListFilterResponseHandler"
}

// Init initializes the handler with the given spec.
func (h *MCPListFilterResponseHandler) Init(_ any, spec *APISpec) error {
	h.Spec = spec
	return nil
}

// Enabled returns true only for MCP APIs.
func (h *MCPListFilterResponseHandler) Enabled() bool {
	return h.Spec.IsMCP()
}

// HandleResponse filters MCP list responses based on session access rights.
func (h *MCPListFilterResponseHandler) HandleResponse(_ http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	state := httpctx.GetJSONRPCRoutingState(req)
	if state == nil {
		return nil
	}

	listCfg := h.listConfig(state.Method)
	if listCfg == nil {
		return nil
	}

	// Skip SSE streaming responses — list methods return JSON, but guard against
	// Streamable HTTP servers that might choose to respond with text/event-stream.
	// Reading the full body of an SSE stream would block indefinitely.
	if ct := res.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		return nil
	}

	rules := h.rulesForAPI(ses, listCfg)
	if rules.IsEmpty() {
		return nil
	}

	body, err := readAndCloseBody(res)
	if err != nil || len(body) == 0 {
		return nil //nolint:nilerr // fail-open: pass through on read error
	}

	newBody, ok := filterJSONRPCBody(body, listCfg, rules)
	if !ok {
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	res.Body = io.NopCloser(bytes.NewReader(newBody))
	res.ContentLength = int64(len(newBody))
	res.Header.Set("Content-Length", strconv.Itoa(len(newBody)))

	return nil
}

// rulesForAPI extracts the access control rules for the current API from the
// session, returning empty rules if the session has no applicable restrictions.
func (h *MCPListFilterResponseHandler) rulesForAPI(ses *user.SessionState, cfg *mcpListConfig) user.AccessControlRules {
	if ses == nil {
		return user.AccessControlRules{}
	}

	accessDef, ok := ses.AccessRights[h.Spec.APIID]
	if !ok || accessDef.MCPAccessRights.IsEmpty() {
		return user.AccessControlRules{}
	}

	return cfg.rulesFrom(accessDef.MCPAccessRights)
}

// listConfig returns the filter configuration for a given JSON-RPC method,
// or nil if the method is not a filterable list method.
func (h *MCPListFilterResponseHandler) listConfig(method string) *mcpListConfig {
	switch method {
	case mcp.MethodToolsList:
		return mcpListConfigs["tools"]
	case mcp.MethodPromptsList:
		return mcpListConfigs["prompts"]
	case mcp.MethodResourcesList:
		return mcpListConfigs["resources"]
	case mcp.MethodResourcesTemplatesList:
		return mcpListConfigs["resourceTemplates"]
	default:
		return nil
	}
}

// --- Shared types, config, and helpers used by both response handler and SSE hook ---

// mcpListConfig holds the configuration for filtering a specific list method.
type mcpListConfig struct {
	arrayKey  string                                                    // JSON key of the array in result (e.g. "tools")
	nameField string                                                    // JSON field to match against rules (e.g. "name", "uri")
	rulesFrom func(rights user.MCPAccessRights) user.AccessControlRules // extracts the relevant rules
}

// mcpListConfigs maps array keys to their filter configurations.
// Both listConfig (method-based lookup) and inferListConfigFromResult
// (result-key-based lookup) reference these shared definitions.
var mcpListConfigs = map[string]*mcpListConfig{
	"tools": {
		arrayKey:  "tools",
		nameField: "name",
		rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Tools },
	},
	"prompts": {
		arrayKey:  "prompts",
		nameField: "name",
		rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Prompts },
	},
	"resources": {
		arrayKey:  "resources",
		nameField: "uri",
		rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Resources },
	},
	"resourceTemplates": {
		arrayKey:  "resourceTemplates",
		nameField: "uriTemplate",
		rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Resources },
	},
}

// jsonRPCResponse represents a JSON-RPC 2.0 response envelope.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// extractStringField extracts a string field from a JSON object.
// Returns empty string if the field doesn't exist or isn't a string.
func extractStringField(raw json.RawMessage, field string) string {
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

// filterItems applies access control rules to a slice of JSON items, returning
// only items that are permitted. Items whose name field cannot be extracted are
// included (fail-open for malformed data).
func filterItems(items []json.RawMessage, nameField string, rules user.AccessControlRules) []json.RawMessage {
	filtered := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		name := extractStringField(item, nameField)
		if name == "" {
			// Can't extract the field — include the item (fail open for malformed data).
			filtered = append(filtered, item)
			continue
		}

		// checkAccessControlRules returns true if denied.
		if !checkAccessControlRules(rules, name) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

// reencodeEnvelope marshals the filtered items back into the JSON-RPC response
// envelope, performing the three-step re-marshal: items -> result -> envelope.
func reencodeEnvelope(envelope *jsonRPCResponse, result map[string]json.RawMessage, arrayKey string, filtered []json.RawMessage) ([]byte, error) {
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

// readAndCloseBody reads the full response body and closes it. On success the
// caller owns the returned bytes; the original body is always closed.
// Returns (nil, nil) when the body is nil.
func readAndCloseBody(res *http.Response) ([]byte, error) {
	if res.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		res.Body = io.NopCloser(bytes.NewReader(nil))
		return nil, err
	}

	return body, nil
}

// filterJSONRPCBody parses a JSON-RPC response body, filters the list items
// according to the given config and rules, and returns the re-encoded body.
// Returns (nil, false) when any parsing or marshalling step fails, signalling
// that the caller should pass through the original body unmodified.
func filterJSONRPCBody(body []byte, cfg *mcpListConfig, rules user.AccessControlRules) ([]byte, bool) {
	var envelope jsonRPCResponse
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

	return filterParsedJSONRPC(&envelope, result, cfg, rules)
}

// filterParsedJSONRPC filters items in an already-parsed JSON-RPC result and
// re-encodes the envelope. Returns (nil, false) when the array key is missing,
// items cannot be parsed, or re-encoding fails.
func filterParsedJSONRPC(envelope *jsonRPCResponse, result map[string]json.RawMessage, cfg *mcpListConfig, rules user.AccessControlRules) ([]byte, bool) {
	itemsRaw, exists := result[cfg.arrayKey]
	if !exists {
		return nil, false
	}

	var items []json.RawMessage
	if err := json.Unmarshal(itemsRaw, &items); err != nil {
		return nil, false
	}

	filtered := filterItems(items, cfg.nameField, rules)

	newBody, err := reencodeEnvelope(envelope, result, cfg.arrayKey, filtered)
	if err != nil {
		return nil, false
	}

	return newBody, true
}
