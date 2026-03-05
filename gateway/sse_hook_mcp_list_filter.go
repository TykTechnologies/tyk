package gateway

import (
	"encoding/json"
	"strings"

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

	// Parse the JSON-RPC envelope.
	var envelope jsonRPCResponse
	if err := json.Unmarshal([]byte(data), &envelope); err != nil {
		return true, nil
	}
	if envelope.Result == nil {
		return true, nil
	}

	// We need to determine the method. JSON-RPC responses don't include the
	// method name, but we can infer the list type from the result keys.
	var result map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return true, nil
	}

	cfg := inferListConfigFromResult(result)
	if cfg == nil {
		return true, nil // not a list response
	}

	accessDef := h.ses.AccessRights[h.apiID]
	rules := cfg.rulesFrom(accessDef.MCPAccessRights)
	if rules.IsEmpty() {
		return true, nil
	}

	// Filter the items array.
	itemsRaw, exists := result[cfg.arrayKey]
	if !exists {
		return true, nil
	}

	var items []json.RawMessage
	if err := json.Unmarshal(itemsRaw, &items); err != nil {
		return true, nil
	}

	filtered := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		name := extractStringField(item, cfg.nameField)
		if name == "" {
			filtered = append(filtered, item)
			continue
		}
		if !checkAccessControlRules(rules, name) {
			filtered = append(filtered, item)
		}
	}

	// Re-encode.
	filteredBytes, err := json.Marshal(filtered)
	if err != nil {
		return true, nil
	}
	result[cfg.arrayKey] = filteredBytes

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return true, nil
	}
	envelope.Result = resultBytes

	newData, err := json.Marshal(envelope)
	if err != nil {
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

// inferListConfigFromResult determines the list type by inspecting which
// well-known array key is present in the JSON-RPC result object.
func inferListConfigFromResult(result map[string]json.RawMessage) *mcpListConfig {
	if _, ok := result["tools"]; ok {
		return &mcpListConfig{
			arrayKey:  "tools",
			nameField: "name",
			rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Tools },
		}
	}
	if _, ok := result["prompts"]; ok {
		return &mcpListConfig{
			arrayKey:  "prompts",
			nameField: "name",
			rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Prompts },
		}
	}
	if _, ok := result["resourceTemplates"]; ok {
		return &mcpListConfig{
			arrayKey:  "resourceTemplates",
			nameField: "uriTemplate",
			rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Resources },
		}
	}
	if _, ok := result["resources"]; ok {
		return &mcpListConfig{
			arrayKey:  "resources",
			nameField: "uri",
			rulesFrom: func(r user.MCPAccessRights) user.AccessControlRules { return r.Resources },
		}
	}
	return nil
}
