package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/TykTechnologies/tyk/ctx"
	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/httpctx"
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
	spec              *APISpec
	ses               *user.SessionState
	req               *http.Request
	expectedID        any
	discoveryGlobal   []user.AccessControlRules
	discoverySession  []user.AccessControlRules
	discoveryVersions []string
	waitingDiscovery  bool
	terminal          bool
	mu                sync.Mutex
}

// NewMCPListFilterSSEHook creates a hook that filters list response events
// based on OAS middleware rules and session access rights for the given API.
// Returns nil if no filtering is needed.
func NewMCPListFilterSSEHook(spec *APISpec, ses *user.SessionState, requests ...*http.Request) *MCPListFilterSSEHook {
	if spec == nil {
		return nil
	}

	discoveryRequest := false
	var req *http.Request
	var expectedID any
	if len(requests) > 0 && requests[0] != nil {
		req = requests[0]
		if state := httpctx.GetJSONRPCRoutingState(req); state != nil {
			discoveryRequest = state.Method == mcp.MethodServerDiscover
			expectedID = state.ID
		}
	}
	if !spec.IsMCP() || (!discoveryRequest && !hasMCPDiscoveryFiltering(spec, ses)) {
		return nil
	}
	hook := &MCPListFilterSSEHook{spec: spec, ses: ses, req: req, expectedID: expectedID, waitingDiscovery: discoveryRequest}
	if discoveryRequest {
		hook.discoveryGlobal, hook.discoverySession = discoveryJSONRPCRuleSets(spec, ses)
		hook.discoveryVersions = spec.SupportedProtocolVersions()
	}
	return hook
}

// FilterEvent inspects an SSE event. If it contains a JSON-RPC list response,
// the primitive array is filtered by access-control rules. Non-list events
// and non-message events pass through unmodified.
func (h *MCPListFilterSSEHook) FilterEvent(event *SSEEvent) (bool, *SSEEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.terminal {
		return false, nil
	}
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

	if h.waitingDiscovery {
		return h.filterDiscoveryEvent(event, []byte(data))
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

// Terminal reports that the hook emitted its one final error event and the
// upstream stream must be closed after that event is drained.
func (h *MCPListFilterSSEHook) Terminal() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.terminal
}

// FailureEvent converts a discovery stream framing failure into the same
// terminal upstream error used for malformed discovery response events.
func (h *MCPListFilterSSEHook) FailureEvent(_ error) *SSEEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.waitingDiscovery || h.terminal {
		return nil
	}
	return h.discoveryFailureEvent(&SSEEvent{Event: "message"})
}

func (h *MCPListFilterSSEHook) filterDiscoveryEvent(event *SSEEvent, data []byte) (bool, *SSEEvent) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return true, h.discoveryFailureEvent(event)
	}
	if _, serverMessage := fields["method"]; serverMessage {
		if mcp.ValidateJSONRPCServerMessage(data) != nil {
			return true, h.discoveryFailureEvent(event)
		}
		return true, nil
	}
	present, matches, idErr := mcp.JSONRPCResponseIDStatus(data, h.expectedID)
	if idErr != nil || !present {
		return true, h.discoveryFailureEvent(event)
	}
	if !matches {
		return true, nil
	}
	filtered, changed, credentialSpecific, err := mcp.FilterDiscoveryBody(
		data,
		h.discoveryGlobal,
		h.discoverySession,
		fixedProtocolSupport(h.discoveryVersions),
	)
	if err != nil {
		return true, h.discoveryFailureEvent(event)
	}
	h.waitingDiscovery = false
	if credentialSpecific {
		markMCPResponseEdited(h.req)
	}
	if !changed {
		return true, nil
	}
	return true, cloneSSEEventWithData(event, filtered)
}

type fixedProtocolSupport []string

func (s fixedProtocolSupport) SupportedProtocolVersions() []string { return s }

func (h *MCPListFilterSSEHook) discoveryFailureEvent(event *SSEEvent) *SSEEvent {
	h.terminal = true
	ctx.SetErrorClassification(h.req, tykerrors.NewErrorClassification(tykerrors.UCF, "invalid_discovery_response").WithSource("MCPDiscoveryFilter"))
	capture := newBufferedResponseWriter()
	body := writeMCPJSONRPCError(capture, h.req, http.StatusBadGateway, "upstream discovery response is invalid")
	markMCPResponseEdited(h.req)
	return cloneSSEEventWithData(event, body)
}

func cloneSSEEventWithData(event *SSEEvent, data []byte) *SSEEvent {
	return &SSEEvent{ID: event.ID, Event: event.Event, Data: []string{string(data)}, Retry: event.Retry}
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
