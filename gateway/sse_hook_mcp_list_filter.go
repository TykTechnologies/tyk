package gateway

import (
	"encoding/json"
	"strings"

	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

// MCPListFilterSSEHook filters MCP list responses (tools/list, prompts/list,
// resources/list, resources/templates/list) inside SSE events when the upstream
// uses Streamable HTTP transport.
//
// In Streamable HTTP, the server may respond to any JSON-RPC method with an
// SSE stream where each "message" event carries a complete JSON-RPC response.
// This hook intercepts those events and applies the same access-control
// filtering as MCPListFilterResponseHandler does for regular HTTP responses.
type MCPListFilterSSEHook struct {
	apiID string
	ses   *user.SessionState
}

// NewMCPListFilterSSEHook creates a hook that filters list response events
// based on the session's MCPAccessRights for the given API.
// Returns nil if no filtering is needed (nil session or no ACL rules).
func NewMCPListFilterSSEHook(apiID string, ses *user.SessionState) *MCPListFilterSSEHook {
	if ses == nil {
		return nil
	}
	accessDef, ok := ses.AccessRights[apiID]
	if !ok || accessDef.MCPAccessRights.IsEmpty() {
		return nil
	}
	return &MCPListFilterSSEHook{apiID: apiID, ses: ses}
}

// FilterEvent inspects an SSE event. If it contains a JSON-RPC list response,
// the primitive array is filtered by access-control rules. Non-list events
// and non-message events pass through unmodified.
func (h *MCPListFilterSSEHook) FilterEvent(event *SSEEvent) (bool, *SSEEvent) {
	// Only "message" events (or events with no explicit type, which default
	// to "message" per the SSE spec) carry JSON-RPC responses.
	if event.Event != "" && event.Event != "message" {
		return true, nil
	}

	// SSE data can span multiple lines; join them to get the full JSON payload.
	data := strings.Join(event.Data, "\n")
	if len(data) == 0 {
		return true, nil
	}

	// Quick check: does this look like it could contain a list result?
	// Avoid parsing JSON for events that clearly aren't list responses.
	if !strings.Contains(data, `"result"`) {
		return true, nil
	}

	newData, ok := h.filterSSEData([]byte(data))
	if !ok {
		return true, nil
	}

	// Build a modified event with the filtered data.
	modified := &SSEEvent{
		ID:    event.ID,
		Event: event.Event,
		Data:  []string{string(newData)},
		Retry: event.Retry,
	}
	return true, modified
}

// filterSSEData parses a JSON-RPC response from SSE event data, infers the
// list type from the result keys, and filters the items. Returns (nil, false)
// when the data is not a filterable list response or any step fails.
func (h *MCPListFilterSSEHook) filterSSEData(data []byte) ([]byte, bool) {
	// Parse the JSON-RPC envelope.
	var envelope mcp.JSONRPCResponse
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, false
	}
	if envelope.Result == nil {
		return nil, false
	}

	// We need to determine the method. JSON-RPC responses don't include the
	// method name, but we can infer the list type from the result keys.
	var result map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return nil, false
	}

	cfg := mcp.InferListConfigFromResult(result)
	if cfg == nil {
		return nil, false
	}

	accessDef := h.ses.AccessRights[h.apiID]
	rules := cfg.RulesFrom(accessDef.MCPAccessRights)
	if rules.IsEmpty() {
		return nil, false
	}

	return mcp.FilterParsedJSONRPC(&envelope, result, cfg, rules)
}
