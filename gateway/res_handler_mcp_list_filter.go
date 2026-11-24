package gateway

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
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
	discovery := state.Method == mcp.MethodServerDiscover
	toolView := remoteMCPToolsListView(h.Spec, state)
	var filter func([]byte) ([]byte, bool, error)
	switch {
	case listCfg != nil:
		ruleSets := effectiveMCPListRuleSets(h.Spec, ses, listCfg)
		if len(ruleSets) == 0 && toolView == nil {
			return nil
		}
		filter = func(body []byte) ([]byte, bool, error) {
			edited := false
			if toolView != nil {
				body, edited = rewriteRemoteMCPToolsList(h.Spec, toolView, state, body, h.logger())
			}
			if filtered, changed := mcp.FilterJSONRPCBodyWithRuleSets(body, listCfg, ruleSets); changed {
				return filtered, true, nil
			}
			return body, edited, nil
		}
	case state.Method == mcp.MethodInitialize:
		ruleSets := effectiveJSONRPCMethodRuleSets(h.Spec, ses)
		if len(ruleSets) == 0 {
			return nil
		}
		filter = func(body []byte) ([]byte, bool, error) {
			filtered, changed := mcp.FilterInitializeCapabilitiesBody(body, ruleSets)
			return filtered, changed, nil
		}
	case state.Method == mcp.MethodServerDiscover:
		globalRules, credentialRules := discoveryJSONRPCRuleSets(h.Spec, ses)
		filter = func(body []byte) ([]byte, bool, error) {
			filtered, changed, credentialSpecific, err := mcp.FilterDiscoveryBody(body, globalRules, credentialRules, h.Spec)
			if credentialSpecific {
				markMCPResponseEdited(req)
				res.Header.Set("Cache-Control", "private, no-store")
			}
			return filtered, changed, err
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

	raw, err := readAndCloseBody(res)
	if err != nil || len(raw) == 0 {
		if discovery {
			replaceInvalidDiscoveryResponse(res, req)
		}
		return nil //nolint:nilerr // fail-open: pass through on read error
	}
	body, decoded := h.decodeBody(res, raw)
	if !decoded && !discovery {
		// Neither access rules nor tool overrides can be applied to a body
		// the Gateway cannot read, so the response fails closed instead of
		// passing through unfiltered.
		replaceUndecodableResponse(res, req)
		return nil
	}
	if discovery && (!decoded || !mcp.JSONRPCResponseIDMatches(body, state.ID)) {
		replaceInvalidDiscoveryResponse(res, req)
		return nil
	}

	newBody, ok, filterErr := filter(body)
	if filterErr != nil && discovery {
		replaceInvalidDiscoveryResponse(res, req)
		return nil
	}
	if !ok {
		// Unedited responses keep the upstream bytes and encoding.
		res.Body = io.NopCloser(bytes.NewReader(raw))
		return nil
	}

	// An edited body is sent decoded, whatever the upstream encoding was.
	res.Header.Del(header.ContentEncoding)
	res.Body = io.NopCloser(bytes.NewReader(newBody))
	res.ContentLength = int64(len(newBody))
	res.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	// The upstream validators describe the unmodified (and possibly encoded)
	// representation.
	res.Header.Del("ETag")
	res.Header.Del("Last-Modified")
	if state.Method != mcp.MethodServerDiscover {
		markMCPResponseEdited(req)
	}

	return nil
}

func replaceInvalidDiscoveryResponse(res *http.Response, req *http.Request) {
	ctx.SetErrorClassification(req, tykerrors.NewErrorClassification(tykerrors.UCF, "invalid_discovery_response").WithSource("MCPDiscoveryFilter"))
	replaceWithBadGatewayResponse(res, req, "upstream discovery response is invalid")
}

// replaceUndecodableResponse fails closed on an upstream response the Gateway
// must filter or rewrite but cannot decode.
func replaceUndecodableResponse(res *http.Response, req *http.Request) {
	ctx.SetErrorClassification(req, tykerrors.NewErrorClassification(tykerrors.UCF, "undecodable_mcp_response").WithSource("MCPListFilter"))
	replaceWithBadGatewayResponse(res, req, "upstream response could not be decoded")
}

func replaceWithBadGatewayResponse(res *http.Response, req *http.Request, message string) {
	capture := newBufferedResponseWriter()
	body := writeMCPJSONRPCError(capture, req, http.StatusBadGateway, message)
	res.StatusCode = http.StatusBadGateway
	res.Body = io.NopCloser(bytes.NewReader(body))
	res.ContentLength = int64(len(body))
	for _, name := range []string{"Age", "Content-Encoding", "ETag", "Expires", "Last-Modified", "Pragma", "Transfer-Encoding"} {
		res.Header.Del(name)
	}
	res.Header.Set("Cache-Control", "no-store")
	res.Header.Set("Content-Type", "application/json")
	res.Header.Set("Content-Length", strconv.Itoa(len(body)))
	markMCPResponseEdited(req)
}

// decodeBody returns the decoded upstream body so it can be filtered and
// rewritten. When the body cannot be decoded it reports false after a
// rate-limited warning, and the response fails closed.
func (h *MCPListFilterResponseHandler) decodeBody(res *http.Response, raw []byte) ([]byte, bool) {
	encoding := mcpResponseContentEncoding(res.Header)
	if encoding == "" {
		return raw, true
	}
	var configured int64
	if h.Gw != nil {
		configured = h.Gw.GetConfig().HttpServerOptions.MaxResponseBodySize
	}
	decoded, err := decodeMCPResponseBody(encoding, raw, mcpDecodeLimit(configured))
	if err != nil {
		warnMCPResponseEncoding(h.Spec, encoding, err, h.logger())
		return nil, false
	}
	return decoded, true
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
