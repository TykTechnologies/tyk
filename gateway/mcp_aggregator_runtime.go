package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	mcpaggregator "github.com/TykTechnologies/tyk/internal/mcp/aggregator"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

const (
	// mcpAggregatorMaxListPages bounds how many tools/list pages are read from
	// one aggregated MCP proxy; a proxy that needs more is omitted.
	mcpAggregatorMaxListPages = 100

	// mcpAggregatorMaxCatalogueTools bounds the tools in one aggregator's
	// merged tools/list. It is far above what an agent can use (clients and
	// models degrade well before a few hundred tools) while still capping the
	// work and memory of one tools/list at 50 aggregated proxies.
	mcpAggregatorMaxCatalogueTools = 10000

	// mcpAggregatorMaxCatalogueBytes bounds the JSON size of the tool
	// definitions in one aggregator's merged tools/list: 10000 tools at about
	// 3 KiB each. It is also the budget for the tools/list responses buffered
	// for one tools/list, shared equally between the aggregated proxies.
	mcpAggregatorMaxCatalogueBytes = 32 << 20

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
	case mcp.MethodToolsList:
		catalogue := mcpAggregatorDispatcher{gw: m.Gw, aggregator: m.Spec}.toolsCatalogue(r)
		writeMCPAggregatorResult(w, state.ID, map[string]any{"tools": catalogue.definitions()})
	default:
		writeMCPAggregatorError(w, state.ID, http.StatusNotFound, mcp.JSONRPCMethodNotFound, "method not supported by MCP aggregator")
	}
	return nil, middleware.StatusRespond
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

// mcpAggregatorCatalogue is the aggregator's tool list in upstream order.
type mcpAggregatorCatalogue struct {
	Tools []mcpAggregatorTool
}

func (c mcpAggregatorCatalogue) definitions() []map[string]json.RawMessage {
	out := make([]map[string]json.RawMessage, 0, len(c.Tools))
	for _, tool := range c.Tools {
		out = append(out, tool.Definition)
	}
	return out
}

// toolsCatalogue lists the tools of every aggregated MCP proxy concurrently.
// A proxy that is not loaded or fails is left out with a warning.
func (d mcpAggregatorDispatcher) toolsCatalogue(parent *http.Request) mcpAggregatorCatalogue {
	ext := d.aggregator.OAS.GetTykMCPAggregatorExtension()
	if ext == nil {
		return mcpAggregatorCatalogue{}
	}

	results := make([][]mcpAggregatorTool, len(ext.Upstreams))
	// Every configured proxy gets the same share of the byte budget, so the
	// responses buffered at once stay within it however the reads interleave,
	// and whether a proxy fits never depends on the others.
	share := mcpAggregatorMaxCatalogueBytes / max(len(ext.Upstreams), 1)
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
			budgeted := d
			budgeted.budget = &mcpAggregatorByteBudget{share: share}
			tools, err := budgeted.listUpstreamTools(parent, upstream)
			if err != nil {
				logMCPAggregatorUpstreamOmitted(d.aggregator.APIID, upstream.APIID, upstream.Alias, mcpAggregatorFailureReason(err))
				return
			}
			results[i] = tools
		}(i)
	}
	wg.Wait()

	var catalogue mcpAggregatorCatalogue
	var catalogueBytes int
	for i, tools := range results {
		size := mcpAggregatorToolsSize(tools)
		if reason := mcpAggregatorCatalogueOverflow(len(catalogue.Tools)+len(tools), catalogueBytes+size); reason != "" {
			ref := ext.Upstreams[i]
			logMCPAggregatorUpstreamOmitted(d.aggregator.APIID, ref.APIID, ref.Alias, reason)
			continue
		}
		catalogue.Tools = append(catalogue.Tools, tools...)
		catalogueBytes += size
	}
	return catalogue
}

// mcpAggregatorCatalogueOverflow says why a catalogue of the given tool count
// and definition size is over the aggregator's bounds, or returns "".
func mcpAggregatorCatalogueOverflow(tools, bytes int) string {
	switch {
	case tools > mcpAggregatorMaxCatalogueTools:
		return fmt.Sprintf("catalogue limit: the aggregator serves at most %d tools", mcpAggregatorMaxCatalogueTools)
	case bytes > mcpAggregatorMaxCatalogueBytes:
		return fmt.Sprintf("catalogue limit: the aggregator serves at most %d bytes of tool definitions", mcpAggregatorMaxCatalogueBytes)
	}
	return ""
}

// mcpAggregatorToolsSize approximates the JSON size of tool definitions as the
// size of their field names and raw values.
func mcpAggregatorToolsSize(tools []mcpAggregatorTool) int {
	var size int
	for _, tool := range tools {
		for key, value := range tool.Definition {
			size += len(key) + len(value)
		}
	}
	return size
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
	var listedBytes int
	for page := 0; ; page++ {
		if page == mcpAggregatorMaxListPages {
			return nil, fmt.Errorf("returned more than %d pages", mcpAggregatorMaxListPages)
		}
		raw, err := d.call(parent, upstream, mcp.MethodToolsList, params)
		if err != nil {
			return nil, err
		}
		// A proxy that lists more than the whole catalogue may hold can never
		// be served, so its pages stop being read and buffered here.
		if listedBytes += len(raw); listedBytes > mcpAggregatorMaxCatalogueBytes {
			return nil, fmt.Errorf("returned more than %d bytes of tools", mcpAggregatorMaxCatalogueBytes)
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
		if len(tools) > mcpAggregatorMaxCatalogueTools {
			return nil, fmt.Errorf("returned more than %d tools", mcpAggregatorMaxCatalogueTools)
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

func writeMCPAggregatorResult(w http.ResponseWriter, id any, result any) {
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	encodeMCPAggregatorResponse(w, map[string]any{
		"jsonrpc": apidef.JsonRPC20,
		"id":      id,
		"result":  result,
	})
}

func writeMCPAggregatorError(w http.ResponseWriter, id any, httpCode, code int, message string) {
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(httpCode)
	encodeMCPAggregatorResponse(w, JSONRPCErrorResponse{
		JSONRPC: apidef.JsonRPC20,
		Error:   JSONRPCError{Code: code, Message: message},
		ID:      id,
	})
}

// encodeMCPAggregatorResponse writes a JSON-RPC response body. The status line
// is already sent, so a failed write, usually a client that went away, can
// only be logged.
func encodeMCPAggregatorResponse(w http.ResponseWriter, body any) {
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.WithError(err).Warn("MCP aggregator could not write the JSON-RPC response")
	}
}
