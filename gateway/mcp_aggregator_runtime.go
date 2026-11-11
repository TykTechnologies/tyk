package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	mcpaggregator "github.com/TykTechnologies/tyk/internal/mcp/aggregator"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/user"
)

const (
	// mcpAggregatorMaxListPages bounds how many tools/list pages are read from
	// one aggregated MCP proxy; a proxy that needs more is omitted.
	mcpAggregatorMaxListPages = 100

	mcpAggregatorUnnamedToolMsg = "MCP aggregator skips aggregated tool without a name"
)

// MCPAggregatorMiddleware serves an MCP aggregator's JSON-RPC methods after the
// aggregator's own middleware chain, including authentication, has run.
type MCPAggregatorMiddleware struct {
	*BaseMiddleware
}

func (m *MCPAggregatorMiddleware) Name() string {
	return "MCPAggregatorMiddleware"
}

func (m *MCPAggregatorMiddleware) EnabledForSpec() bool {
	return m.Spec != nil && m.Spec.APIDefinition != nil && m.Spec.IsMCPAggregator()
}

//nolint:staticcheck // ST1008: middleware interface requires (error, int).
func (m *MCPAggregatorMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// A pending rewrite is the JSON-RPC router's hop into the method's VEM
	// chain; the aggregator answers once that chain has completed.
	if ctxGetURLRewriteTarget(r) != nil {
		return nil, http.StatusOK
	}

	state := httpctx.GetJSONRPCRoutingState(r)
	if r.Method != http.MethodPost || state == nil {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return nil, middleware.StatusRespond
	}

	switch state.Method {
	case mcp.MethodServerDiscover:
		writeMCPAggregatorResult(w, state.ID, map[string]any{
			"resultType":        "complete",
			"supportedVersions": m.Spec.SupportedProtocolVersions(),
			"capabilities":      mcpAggregatorCapabilities(),
			"_meta":             map[string]any{mcpsdk.MetaKeyServerInfo: m.serverInfo()},
		})
	case mcp.MethodInitialize:
		// Ingress admits initialize only when it declares 2026-07-28.
		writeMCPAggregatorResult(w, state.ID, map[string]any{
			"protocolVersion": mcp.ModernProtocolVersion,
			"capabilities":    mcpAggregatorCapabilities(),
			"serverInfo":      m.serverInfo(),
		})
	case mcp.MethodNotificationsInitialized:
		if state.ID != nil {
			writeMCPAggregatorError(w, state.ID, http.StatusBadRequest, mcp.JSONRPCInvalidRequest, "notifications must not carry an id")
			break
		}
		// The aggregator keeps no session, so the handshake needs no state.
		w.WriteHeader(http.StatusAccepted)
	case mcp.MethodPing:
		writeMCPAggregatorResult(w, state.ID, map[string]any{})
	case mcp.MethodToolsList:
		catalogue := mcpAggregatorDispatcher{gw: m.Gw, aggregator: m.Spec}.toolsCatalogue(r)
		writeMCPAggregatorResult(w, state.ID, m.toolsListResult(catalogue, ctxGetSession(r)))
	case mcp.MethodToolsCall:
		m.serveToolsCall(w, r, state)
	default:
		writeMCPAggregatorError(w, state.ID, http.StatusNotFound, mcp.JSONRPCMethodNotFound, "method not supported by MCP aggregator")
	}
	return nil, middleware.StatusRespond
}

// mcpAggregatorCapabilities lists what an aggregator serves: tools only.
func mcpAggregatorCapabilities() map[string]any {
	return map[string]any{"tools": map[string]any{}}
}

func (m *MCPAggregatorMiddleware) serverInfo() map[string]any {
	return map[string]any{"name": m.Spec.Name, "version": VERSION}
}

// mcpAggregatorTool is one tool of an aggregated MCP proxy exposed under its
// namespaced name.
type mcpAggregatorTool struct {
	Name             string
	Alias            string
	UpstreamAPIID    string
	UpstreamToolName string
	Definition       map[string]json.RawMessage
}

// mcpAggregatorCatalogue is the aggregator's tool list, sorted by aggregated
// tool name so its order never depends on which proxy answered first.
type mcpAggregatorCatalogue struct {
	Tools []mcpAggregatorTool
}

// toolsListResult is the tools/list result for one consumer: the catalogue
// with the consumer's MCP tool rules applied to the aggregated names. The list
// is built per credential, so it is always private and immediately stale,
// whatever cache hints the aggregated proxies sent.
func (m *MCPAggregatorMiddleware) toolsListResult(catalogue mcpAggregatorCatalogue, session *user.SessionState) map[string]json.RawMessage {
	cfg := mcp.ListFilterConfigs["tools"]
	items := make([]json.RawMessage, 0, len(catalogue.Tools))
	for _, tool := range catalogue.Tools {
		if definition, err := marshalMCPAggregatorJSON(tool.Definition); err == nil {
			items = append(items, definition)
		}
	}
	items = mcp.FilterItemsWithRuleSets(items, cfg.NameField, effectiveMCPListRuleSets(m.Spec, session, cfg))
	tools, err := marshalMCPAggregatorJSON(items)
	if err != nil {
		tools = json.RawMessage(`[]`)
	}
	result := map[string]json.RawMessage{"tools": tools}
	mcp.SetPrivateCacheHints(result)
	return result
}

// toolsCatalogue lists the tools of every aggregated MCP proxy concurrently.
// A proxy that is not loaded or fails is left out with a warning.
func (d mcpAggregatorDispatcher) toolsCatalogue(parent *http.Request) mcpAggregatorCatalogue {
	ext := d.aggregator.OAS.GetTykMCPAggregatorExtension()
	if ext == nil {
		return mcpAggregatorCatalogue{}
	}

	results := make([][]mcpAggregatorTool, len(ext.Upstreams))
	var wg sync.WaitGroup
	for i, ref := range ext.Upstreams {
		upstream := mcpaggregator.Upstream{APIID: ref.APIID, Alias: ref.Alias, Tools: ref.Tools}
		if status := classifyMCPAggregatorUpstream(d.aggregator.OrgID, d.gw.getApiSpec(ref.APIID)); status != mcpAggregatorUpstreamAdmitted {
			logMCPAggregatorUpstreamOmitted(d.aggregator.APIID, ref.APIID, ref.Alias, status.String())
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tools, err := d.listUpstreamTools(parent, upstream)
			var mismatch *mcpAggregatorVersionMismatchError
			switch {
			case errors.As(err, &mismatch):
				logMCPAggregatorVersionMismatch(d.aggregator.APIID, upstream.APIID, upstream.Alias, mismatch)
				return
			case err != nil:
				logMCPAggregatorUpstreamOmitted(d.aggregator.APIID, upstream.APIID, upstream.Alias, mcpAggregatorFailureReason(err))
				return
			}
			results[i] = tools
		}(i)
	}
	wg.Wait()

	var catalogue mcpAggregatorCatalogue
	for _, tools := range results {
		catalogue.Tools = append(catalogue.Tools, tools...)
	}
	sort.SliceStable(catalogue.Tools, func(i, j int) bool { return catalogue.Tools[i].Name < catalogue.Tools[j].Name })
	return catalogue
}

// logMCPAggregatorVersionMismatch warns that an aggregated MCP proxy is left
// out because it no longer serves 2026-07-28.
func logMCPAggregatorVersionMismatch(aggregatorAPIID, upstreamAPIID, alias string, mismatch *mcpAggregatorVersionMismatchError) {
	log.WithFields(logrus.Fields{
		"aggregator_api_id":    aggregatorAPIID,
		"upstream_api_id":      upstreamAPIID,
		"alias":                alias,
		"mcp_protocol_version": mcp.ModernProtocolVersion,
		"reason":               fmt.Sprintf("version mismatch: does not support MCP version %s: %s", mcp.ModernProtocolVersion, mismatch.Detail),
	}).Warn(mcpAggregatorUpstreamOmittedMsg)
}

func mcpAggregatorFailureReason(err error) string {
	if errors.Is(err, errMCPAggregatorUpstreamNotLoaded) {
		return err.Error()
	}
	return "tools/list failed: " + err.Error()
}

func (d mcpAggregatorDispatcher) listUpstreamTools(parent *http.Request, upstream mcpaggregator.Upstream) ([]mcpAggregatorTool, error) {
	var tools []mcpAggregatorTool
	params := map[string]any{}
	seenCursors := map[string]struct{}{}
	for page := 0; ; page++ {
		if page == mcpAggregatorMaxListPages {
			return nil, fmt.Errorf("returned more than %d pages", mcpAggregatorMaxListPages)
		}
		raw, err := d.call(parent, upstream, mcp.MethodToolsList, params)
		if err != nil {
			return nil, err
		}
		var result struct {
			Tools      []map[string]json.RawMessage `json:"tools"`
			NextCursor string                       `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, err
		}
		for _, definition := range result.Tools {
			var name string
			if json.Unmarshal(definition["name"], &name) != nil || name == "" {
				log.WithFields(logrus.Fields{
					"aggregator_api_id": d.aggregator.APIID,
					"upstream_api_id":   upstream.APIID,
					"alias":             upstream.Alias,
				}).Warn(mcpAggregatorUnnamedToolMsg)
				continue
			}
			aggregatedName := mcpaggregator.ToolName(upstream.Alias, name)
			encodedName, err := json.Marshal(aggregatedName)
			if err != nil {
				return nil, err
			}
			definition["name"] = encodedName
			tools = append(tools, mcpAggregatorTool{
				Name:             aggregatedName,
				Alias:            upstream.Alias,
				UpstreamAPIID:    upstream.APIID,
				UpstreamToolName: name,
				Definition:       definition,
			})
		}
		if result.NextCursor == "" {
			return tools, nil
		}
		if _, repeated := seenCursors[result.NextCursor]; repeated {
			return nil, fmt.Errorf("repeated cursor %q", result.NextCursor)
		}
		seenCursors[result.NextCursor] = struct{}{}
		params = map[string]any{"cursor": result.NextCursor}
	}
}

// marshalMCPAggregatorJSON marshals without HTML-escaping, so text from
// aggregated proxies keeps the characters it was sent with.
func marshalMCPAggregatorJSON(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// writeMCPAggregatorResult writes a JSON-RPC result without HTML-escaping, so
// descriptors from aggregated proxies keep their text as sent.
func writeMCPAggregatorResult(w http.ResponseWriter, id any, result any) {
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]any{
		"jsonrpc": apidef.JsonRPC20,
		"id":      id,
		"result":  result,
	})
}

func writeMCPAggregatorError(w http.ResponseWriter, id any, httpCode, code int, message string) {
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(JSONRPCErrorResponse{
		JSONRPC: apidef.JsonRPC20,
		Error:   JSONRPCError{Code: code, Message: message},
		ID:      id,
	})
}
