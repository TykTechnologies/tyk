package gateway

import (
	"bytes"
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
	var filter func([]byte) ([]byte, bool)
	switch {
	case listCfg != nil:
		ruleSets := effectiveMCPListRuleSets(h.Spec, ses, listCfg)
		if len(ruleSets) == 0 {
			return nil
		}
		filter = func(body []byte) ([]byte, bool) {
			return mcp.FilterJSONRPCBodyWithRuleSets(body, listCfg, ruleSets)
		}
	case state.Method == mcp.MethodInitialize:
		ruleSets := effectiveJSONRPCMethodRuleSets(h.Spec, ses)
		if len(ruleSets) == 0 {
			return nil
		}
		filter = func(body []byte) ([]byte, bool) {
			return mcp.FilterInitializeCapabilitiesBody(body, ruleSets)
		}
	default:
		return nil
	}

	// Skip SSE streaming responses — list methods return JSON, but guard against
	// Streamable HTTP servers that might choose to respond with text/event-stream.
	// Reading the full body of an SSE stream would block indefinitely.
	if ct := res.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		return nil
	}

	body, err := readAndCloseBody(res)
	if err != nil || len(body) == 0 {
		return nil //nolint:nilerr // fail-open: pass through on read error
	}

	newBody, ok := filter(body)
	if !ok {
		res.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	res.Body = io.NopCloser(bytes.NewReader(newBody))
	res.ContentLength = int64(len(newBody))
	res.Header.Set("Content-Length", strconv.Itoa(len(newBody)))

	return nil
}

// listConfig returns the filter configuration for a given JSON-RPC method,
// or nil if the method is not a filterable list method.
func (h *MCPListFilterResponseHandler) listConfig(method string) *mcp.ListFilterConfig {
	switch method {
	case mcp.MethodToolsList:
		return mcp.ListFilterConfigs["tools"]
	case mcp.MethodPromptsList:
		return mcp.ListFilterConfigs["prompts"]
	case mcp.MethodResourcesList:
		return mcp.ListFilterConfigs["resources"]
	case mcp.MethodResourcesTemplatesList:
		return mcp.ListFilterConfigs["resourceTemplates"]
	default:
		return nil
	}
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
