package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

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

	mcpAggregatorSelectedToolMissingMsg = "MCP aggregator omits selected tool the aggregated MCP proxy does not expose"
	mcpAggregatorToolNameTooLongMsg     = "MCP aggregator omits aggregated tool whose name exceeds the MCP tool name limit"
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

	if timeout := mcpAggregatorTimeout(m.Spec, r); timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
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
	case mcp.MethodNotificationsInitialized, mcp.MethodNotificationsCancelled:
		// On 2026-07-28 every request is its own HTTP exchange, so a call is
		// cancelled by closing its connection, which cancels the in-flight
		// upstream call. A notifications/cancelled arrives on another exchange
		// and request ids are only unique per client, so it is acknowledged
		// without acting on it, as the MCP SDK's stateless servers do.
		if state.ID != nil {
			writeMCPAggregatorError(w, state.ID, http.StatusBadRequest, mcp.JSONRPCInvalidRequest, "notifications must not carry an id")
			break
		}
		w.WriteHeader(http.StatusAccepted)
	case mcp.MethodPing:
		writeMCPAggregatorResult(w, state.ID, map[string]any{})
	case mcp.MethodToolsList:
		catalogue := mcpAggregatorDispatcher{gw: m.Gw, aggregator: m.Spec}.toolsCatalogue(r)
		if mcpAggregatorClientGone(r) {
			break
		}
		writeMCPAggregatorResult(w, state.ID, m.toolsListResult(catalogue, ctxGetSession(r)))
	case mcp.MethodToolsCall:
		m.serveToolsCall(w, r, state)
	default:
		writeMCPAggregatorError(w, state.ID, http.StatusNotFound, mcp.JSONRPCMethodNotFound, "method not supported by MCP aggregator")
	}
	return nil, middleware.StatusRespond
}

// mcpAggregatorTimeout is the aggregator's API-level enforced timeout
// (upstream.enforceTimeout in the OAS definition), which bounds every call the
// aggregator makes to its aggregated MCP proxies for one request.
func mcpAggregatorTimeout(spec *APISpec, r *http.Request) time.Duration {
	version, _ := spec.Version(r)
	if version == nil || version.GlobalEnforceTimeoutDisabled || version.GlobalEnforceTimeout <= 0 {
		return 0
	}
	return time.Duration(version.GlobalEnforceTimeout)
}

// mcpAggregatorClientGone reports an agent that cancelled its request: there is
// no one to send a result to.
func mcpAggregatorClientGone(r *http.Request) bool {
	return errors.Is(r.Context().Err(), context.Canceled)
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

// listUpstreamTools lists the tools an aggregated MCP proxy exposes now and
// keeps the ones the aggregator selects. A selected tool the proxy no longer
// exposes is left out with a warning, so the aggregator keeps serving the rest.
func (d mcpAggregatorDispatcher) listUpstreamTools(parent *http.Request, upstream mcpaggregator.Upstream) ([]mcpAggregatorTool, error) {
	spec, err := d.upstreamSpec(upstream.APIID)
	if err != nil {
		return nil, err
	}
	exposed, err := d.exposedTools(parent, spec, upstream.Alias, d.loopTrust(spec))
	if err != nil {
		return nil, err
	}
	var tools []mcpAggregatorTool
	names := make(map[string]struct{}, len(exposed))
	selection := newMCPAggregatorToolSelection(upstream)
	for _, tool := range exposed {
		names[tool.Name] = struct{}{}
		if !selection.selects(tool.Name) {
			continue
		}
		aggregatedName := mcpaggregator.ToolName(upstream.Alias, tool.Name)
		if !mcpAggregatorNameFits(aggregatedName) {
			log.WithFields(logrus.Fields{
				"aggregator_api_id": d.aggregator.APIID,
				"upstream_api_id":   upstream.APIID,
				"alias":             upstream.Alias,
				"tool":              tool.Name,
				"reason":            fmt.Sprintf("%q plus the tool name is %d characters, over the %d character limit for MCP tool names", upstream.Alias+mcpaggregator.NamespaceSeparator, utf8.RuneCountInString(aggregatedName), mcpaggregator.MaxToolNameLength),
			}).Warn(mcpAggregatorToolNameTooLongMsg)
			continue
		}
		encodedName, err := json.Marshal(aggregatedName)
		if err != nil {
			return nil, err
		}
		tool.Definition["name"] = encodedName
		tools = append(tools, mcpAggregatorTool{
			Name:             aggregatedName,
			Alias:            upstream.Alias,
			UpstreamAPIID:    upstream.APIID,
			UpstreamToolName: tool.Name,
			Definition:       tool.Definition,
		})
	}
	d.warnSelectedToolsMissing(upstream, names)
	return tools, nil
}

// mcpAggregatorExposedTool is one tool as an aggregated MCP proxy lists it,
// under the proxy's own name.
type mcpAggregatorExposedTool struct {
	Name       string
	Definition map[string]json.RawMessage
}

// exposedTools reads every tools/list page of an aggregated MCP proxy under
// the given loop trust: the proxy's complete current tool view, after its own
// renames and restrictions. Admission and the runtime share it, so a selection
// is checked against the same view the aggregator serves from.
func (d mcpAggregatorDispatcher) exposedTools(parent *http.Request, spec *APISpec, alias string, trust *mcpAggregatorLoopTrust) ([]mcpAggregatorExposedTool, error) {
	var tools []mcpAggregatorExposedTool
	params := map[string]any{}
	seenCursors := map[string]struct{}{}
	var listedBytes int
	for page := 0; ; page++ {
		if page == mcpAggregatorMaxListPages {
			return nil, fmt.Errorf("returned more than %d pages", mcpAggregatorMaxListPages)
		}
		raw, err := d.send(parent, spec, mcp.MethodToolsList, params, trust)
		if err != nil {
			return nil, err
		}
		// Reading stops once a proxy lists more than the whole catalogue may
		// hold, so one proxy cannot make the aggregator buffer more than that.
		// Such a proxy is left out even when only some of its tools are
		// selected.
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
					"upstream_api_id":   spec.APIID,
					"alias":             alias,
				}).Warn(mcpAggregatorUnnamedToolMsg)
				continue
			}
			tools = append(tools, mcpAggregatorExposedTool{Name: name, Definition: definition})
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

func (d mcpAggregatorDispatcher) warnSelectedToolsMissing(upstream mcpaggregator.Upstream, exposed map[string]struct{}) {
	for _, tool := range upstream.Tools {
		if _, ok := exposed[tool]; !ok {
			log.WithFields(logrus.Fields{
				"aggregator_api_id": d.aggregator.APIID,
				"upstream_api_id":   upstream.APIID,
				"alias":             upstream.Alias,
				"tool":              tool,
			}).Warn(mcpAggregatorSelectedToolMissingMsg)
		}
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
