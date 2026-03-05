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

	// Determine which list method this is and what to filter.
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

	// Get session access rights for this API.
	if ses == nil {
		return nil
	}

	accessDef, ok := ses.AccessRights[h.Spec.APIID]
	if !ok {
		return nil
	}

	if accessDef.MCPAccessRights.IsEmpty() {
		return nil
	}

	rules := listCfg.rulesFrom(accessDef.MCPAccessRights)
	if rules.IsEmpty() {
		return nil
	}

	// Read response body.
	if res.Body == nil {
		return nil
	}

	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil //nolint:nilerr // fail-open: pass through on read error
	}

	if len(body) == 0 {
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	// Parse the JSON-RPC response envelope.
	var envelope jsonRPCResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		// Malformed JSON — pass through unmodified.
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil //nolint:nilerr // fail-open: pass through malformed JSON
	}

	// If there's no result (e.g. error response), pass through.
	if envelope.Result == nil {
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil //nolint:nilerr // fail-open: pass through unparseable result
	}

	arrayKey := listCfg.arrayKey
	itemsRaw, exists := result[arrayKey]
	if !exists {
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	var items []json.RawMessage
	if err := json.Unmarshal(itemsRaw, &items); err != nil {
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil //nolint:nilerr // fail-open: pass through unparseable items array
	}

	// Filter items based on access control rules.
	nameField := listCfg.nameField
	filtered := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		name := extractStringField(item, nameField)
		if name == "" {
			// If we can't extract the field, include the item (fail open for malformed data).
			filtered = append(filtered, item)
			continue
		}

		// checkAccessControlRules returns true if denied.
		if !checkAccessControlRules(rules, name) {
			filtered = append(filtered, item)
		}
	}

	// Re-encode the filtered array back into the result.
	filteredBytes, err := json.Marshal(filtered)
	if err != nil {
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil //nolint:nilerr // fail-open: pass through on marshal error
	}

	result[arrayKey] = filteredBytes

	resultBytes, err := json.Marshal(result)
	if err != nil {
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil //nolint:nilerr // fail-open: pass through on marshal error
	}

	envelope.Result = resultBytes

	newBody, err := json.Marshal(envelope)
	if err != nil {
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil //nolint:nilerr // fail-open: pass through on marshal error
	}

	res.Body = io.NopCloser(bytes.NewReader(newBody))
	res.ContentLength = int64(len(newBody))
	res.Header.Set("Content-Length", strconv.Itoa(len(newBody)))

	return nil
}

// mcpListConfig holds the configuration for filtering a specific list method.
type mcpListConfig struct {
	arrayKey  string                                                    // JSON key of the array in result (e.g. "tools")
	nameField string                                                    // JSON field to match against rules (e.g. "name", "uri")
	rulesFrom func(rights user.MCPAccessRights) user.AccessControlRules // extracts the relevant rules
}

// listConfig returns the filter configuration for a given JSON-RPC method,
// or nil if the method is not a filterable list method.
func (h *MCPListFilterResponseHandler) listConfig(method string) *mcpListConfig {
	switch method {
	case mcp.MethodToolsList:
		return &mcpListConfig{
			arrayKey:  "tools",
			nameField: "name",
			rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Tools },
		}
	case mcp.MethodPromptsList:
		return &mcpListConfig{
			arrayKey:  "prompts",
			nameField: "name",
			rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Prompts },
		}
	case mcp.MethodResourcesList:
		return &mcpListConfig{
			arrayKey:  "resources",
			nameField: "uri",
			rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Resources },
		}
	case mcp.MethodResourcesTemplatesList:
		return &mcpListConfig{
			arrayKey:  "resourceTemplates",
			nameField: "uriTemplate",
			rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Resources },
		}
	default:
		return nil
	}
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
