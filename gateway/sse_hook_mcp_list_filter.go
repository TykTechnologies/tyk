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
	spec *APISpec
	ses  *user.SessionState
}

// NewMCPListFilterSSEHook creates a hook that filters list response events
// based on OAS middleware rules and session access rights for the given API.
// Returns nil if no filtering is needed.
func NewMCPListFilterSSEHook(spec *APISpec, ses *user.SessionState) *MCPListFilterSSEHook {
	if spec == nil {
		return nil
	}

	if !hasMCPDiscoveryFiltering(spec, ses) {
		return nil
	}
	return &MCPListFilterSSEHook{spec: spec, ses: ses}
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
	if cfg != nil {
		ruleSets := effectiveMCPListRuleSets(h.spec, h.ses, cfg)
		if len(ruleSets) == 0 {
			return nil, false
		}
		return mcp.FilterParsedJSONRPCWithRuleSets(&envelope, result, cfg, ruleSets)
	}

	ruleSets := effectiveJSONRPCMethodRuleSets(h.spec, h.ses)
	if len(ruleSets) == 0 {
		return nil, false
	}
	return mcp.FilterInitializeCapabilitiesParsed(&envelope, result, ruleSets)
}

func hasMCPDiscoveryFiltering(spec *APISpec, ses *user.SessionState) bool {
	if !oasPrimitiveRules(spec, mcp.ListFilterConfigs["tools"]).IsEmpty() ||
		!oasPrimitiveRules(spec, mcp.ListFilterConfigs["prompts"]).IsEmpty() ||
		!oasPrimitiveRules(spec, mcp.ListFilterConfigs["resources"]).IsEmpty() ||
		!oasJSONRPCMethodRules(spec).IsEmpty() {

		return true
	}

	if spec == nil || ses == nil {
		return false
	}

	accessDef, ok := ses.AccessRights[spec.APIID]
	if !ok {
		return false
	}

	return !accessDef.MCPAccessRights.IsEmpty() || !accessDef.JSONRPCMethodsAccessRights.IsEmpty()
}
