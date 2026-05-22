package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/TykTechnologies/tyk/apidef/oas"
	tykctx "github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	mcpadapter "github.com/TykTechnologies/tyk/internal/mcp/adapter"
	mcppairing "github.com/TykTechnologies/tyk/internal/mcp/pairing"
	"github.com/TykTechnologies/tyk/user"
)

const (
	// mcpAdapterListenPathPrefix is the listen path stem given to every
	// synthesised adapter spec. Adapter specs are Internal so this path is
	// never reachable from the public muxer; the prefix is only there to
	// satisfy listen-path validation in loadHTTPService.
	mcpAdapterListenPathPrefix = "/__tyk-mcp-server/"
	mcpLoopExactIDPrefix       = "id:"
)

func exactMCPAPILoopTarget(apiID string) string {
	return mcpLoopExactIDPrefix + apiID
}

// synthesiseMCPAdapters walks loaded MCP-managed proxies and, for every unique
// `tyk://<rest-api-id>__mcp-server` upstream target, emits one shared Internal
// adapter APISpec into tmpSpecRegister and tmpSpecHandles.
//
// Adapter specs:
//   - have deterministic APIID `<rest-apiid>__mcp-server`
//   - inherit OrgID from the source REST spec (multi-tenant safety)
//   - are Internal:true (skipped by the public muxer per api_loader.go:196)
//   - are MarkedAsMCP() so JSONRPCMiddleware wires into the chain
//   - carry a fresh primitive catalogue produced from the REST OAS — pure,
//     gateway-agnostic, run on every reload
//
// The function is best-effort per spec: if derivation fails for one
// source REST API, the error is logged and the loader continues.
//
// Returns the synthesised specs (caller registers them) — they are also
// recorded in the adapter map computed alongside the pairing index.
func (gw *Gateway) synthesiseMCPAdapters(
	tmpSpecRegister map[string]*APISpec,
	tmpSpecHandles *sync.Map,
	apisByListen map[string]int,
	gs *generalStores,
	muxer *proxyMux,
) []*APISpec {

	var synthesised []*APISpec

	for _, restID := range referencedMCPAdapterRESTIDs(tmpSpecRegister) {
		rest := tmpSpecRegister[restID]
		if rest == nil || rest.APIDefinition == nil {
			continue
		}

		adapter, err := gw.buildAdapterSpecForProxies(rest, tmpSpecRegister)
		if err != nil {
			mainLog.WithError(err).WithField("rest_api_id", rest.APIID).
				Error("failed to synthesise MCP adapter spec")
			continue
		}
		mainLog.WithFields(map[string]interface{}{
			"rest_api_id":     rest.APIID,
			"adapter_api_id":  adapter.APIID,
			"primitive_count": len(adapter.DerivedPrimitives),
			"tool_count":      len(adapter.DerivedTools),
		}).Debug("synthesised MCP adapter")

		tmpSpecRegister[adapter.APIID] = adapter

		handle, err := gw.loadHTTPService(adapter, apisByListen, gs, muxer)
		if err != nil {
			mainLog.WithError(err).WithField("adapter_api_id", adapter.APIID).
				Error("failed to load synthetic MCP adapter chain")
			delete(tmpSpecRegister, adapter.APIID)
			continue
		}
		tmpSpecHandles.Store(adapter.APIID, handle)

		synthesised = append(synthesised, adapter)
	}

	return synthesised
}

// rebuildMCPPairing walks the in-flight spec register and replaces the pairing
// index (gw.mcpPairing) atomically with fresh REST→adapter and REST→allowed
// proxy maps.
//
// A proxy is recognised by:
//   - Proxy.TargetURL has scheme `tyk` and host equal to an adapter
//     APIID registered in tmpSpecRegister
//   - The candidate is not itself a synthetic adapter
//   - REST/proxy OrgIDs match (cross-org targeting is refused; the
//     admit-time validator should already have caught it, this is
//     defence in depth)
func (gw *Gateway) rebuildMCPPairing(tmpSpecRegister map[string]*APISpec) {
	allowedProxies, adapterMap := computeMCPPairing(tmpSpecRegister)
	gw.mcpPairing.Set(adapterMap, allowedProxies)
}

// computeMCPPairing is the pure (gateway-free) core of
// rebuildMCPPairing — exported within the package for unit testing.
// Returns (restID→allowed proxy set, restID→adapterID).
func computeMCPPairing(specs map[string]*APISpec) (allowedProxies mcppairing.AllowedProxySet, adapter map[string]string) {
	allowedProxies = mcppairing.AllowedProxySet{}
	adapter = map[string]string{}

	for _, spec := range specs {
		if spec == nil || spec.APIDefinition == nil {
			continue
		}
		if spec.IsSyntheticMCPAdapter {
			adapter[spec.SourceRESTAPIID] = spec.APIID
			continue
		}
		if !spec.IsMCPManaged() {
			continue
		}
		adapterID, restID, ok := pairedMCPAdapterTarget(spec.Proxy.TargetURL)
		if !ok {
			continue
		}
		rest, restOK := specs[restID]
		_, adapterOK := specs[adapterID]
		if !adapterOK || !restOK || rest == nil {
			continue
		}
		if rest.OrgID != spec.OrgID {
			continue
		}
		if allowedProxies[restID] == nil {
			allowedProxies[restID] = map[string]struct{}{}
		}
		allowedProxies[restID][spec.APIID] = struct{}{}
	}
	return allowedProxies, adapter
}

func referencedMCPAdapterRESTIDs(specs map[string]*APISpec) []string {
	set := referencedMCPAdapterRESTIDSet(specs)
	ids := make([]string, 0, len(set))
	for restID := range set {
		ids = append(ids, restID)
	}
	sort.Strings(ids)
	return ids
}

func referencedMCPAdapterRESTIDSet(specs map[string]*APISpec) map[string]struct{} {
	out := map[string]struct{}{}
	for _, spec := range specs {
		if spec == nil || spec.APIDefinition == nil || spec.IsSyntheticMCPAdapter || !spec.IsMCPManaged() {
			continue
		}
		_, restID, ok := pairedMCPAdapterTarget(spec.Proxy.TargetURL)
		if !ok {
			continue
		}
		rest := specs[restID]
		if rest == nil || rest.APIDefinition == nil {
			continue
		}
		if rest.OrgID != spec.OrgID {
			continue
		}
		out[restID] = struct{}{}
	}
	return out
}

func referencedMCPAdapterRESTIDSetFromSpecs(specs []*APISpec) map[string]struct{} {
	byID := make(map[string]*APISpec, len(specs))
	for _, spec := range specs {
		if spec == nil || spec.APIDefinition == nil {
			continue
		}
		byID[spec.APIID] = spec
	}
	return referencedMCPAdapterRESTIDSet(byID)
}

// buildAdapterSpec constructs an in-memory adapter APISpec paired with
// the given REST APISpec. The returned spec is ready to be passed to
// loadHTTPService — no further mutation is required.
func (gw *Gateway) buildAdapterSpec(rest *APISpec) (*APISpec, error) {
	return gw.buildAdapterSpecForProxies(rest, nil)
}

func (gw *Gateway) buildAdapterSpecForProxies(rest *APISpec, specs map[string]*APISpec) (*APISpec, error) {
	if rest == nil || rest.APIDefinition == nil {
		return nil, fmt.Errorf("nil source REST spec")
	}

	catalogue, err := deriveMCPAdapterCatalogueForProxies(rest, specs)
	if err != nil {
		return nil, err
	}
	logMCPAdapterDeriveWarnings(rest.APIID, catalogue.warnings)

	adapter := gw.newSyntheticMCPAdapterSpec(rest, catalogue)
	if err := gw.attachSyntheticMCPAdapterRuntime(adapter, catalogue.tools); err != nil {
		return nil, err
	}

	return adapter, nil
}

type mcpAdapterCatalogue struct {
	primitives     []oas.DerivedPrimitive
	tools          []oas.DerivedTool
	warnings       []oas.DeriveWarning
	proxyToolViews map[string]oas.MCPToolView
}

func deriveMCPAdapterCatalogueForProxies(rest *APISpec, specs map[string]*APISpec) (mcpAdapterCatalogue, error) {
	primitives, warnings, err := oas.DeriveSourcePrimitives(&rest.OAS)
	if err != nil {
		return mcpAdapterCatalogue{}, fmt.Errorf("derive MCP primitives: %w", err)
	}
	canonicalTools := oas.ToolPrimitives(primitives)
	proxyViews, err := deriveMCPProxyToolViews(rest, specs)
	if err != nil {
		return mcpAdapterCatalogue{}, err
	}

	tools, err := unionMCPProxyToolViewTools(canonicalTools, proxyViews)
	if err != nil {
		return mcpAdapterCatalogue{}, err
	}

	return mcpAdapterCatalogue{
		primitives:     primitives,
		tools:          tools,
		warnings:       warnings,
		proxyToolViews: proxyViews,
	}, nil
}

func deriveMCPProxyToolViews(rest *APISpec, specs map[string]*APISpec) (map[string]oas.MCPToolView, error) {
	if rest == nil || rest.APIDefinition == nil || len(specs) == 0 {
		return nil, nil
	}

	proxyIDs := sortedMCPProxyIDsForREST(rest, specs)
	if len(proxyIDs) == 0 {
		return nil, nil
	}

	views := make(map[string]oas.MCPToolView, len(proxyIDs))
	for _, proxyID := range proxyIDs {
		proxy := specs[proxyID]
		view, _, err := oas.DeriveMCPToolView(&rest.OAS, proxy.OAS.GetTykMCPServerExtension())
		if err != nil {
			return nil, fmt.Errorf("build MCP tool view for proxy %q: %w", proxy.APIID, err)
		}
		views[proxy.APIID] = view
	}
	return views, nil
}

func sortedMCPProxyIDsForREST(rest *APISpec, specs map[string]*APISpec) []string {
	ids := make([]string, 0, len(specs))
	for _, spec := range specs {
		if spec == nil || spec.APIDefinition == nil || spec.IsSyntheticMCPAdapter || !spec.IsMCPManaged() {
			continue
		}
		_, restID, ok := pairedMCPAdapterTarget(spec.Proxy.TargetURL)
		if !ok || restID != rest.APIID || spec.OrgID != rest.OrgID {
			continue
		}
		ids = append(ids, spec.APIID)
	}
	sort.Strings(ids)
	return ids
}

func unionMCPProxyToolViewTools(canonicalTools []oas.DerivedTool, proxyViews map[string]oas.MCPToolView) ([]oas.DerivedTool, error) {
	if len(proxyViews) == 0 {
		return canonicalTools, nil
	}

	byName := map[string]oas.DerivedTool{}
	for proxyID, view := range proxyViews {
		for _, tool := range view.Tools {
			if existing, ok := byName[tool.Name]; ok {
				if derivedToolSourceIdentity(existing) != derivedToolSourceIdentity(tool) {
					return nil, fmt.Errorf("MCP tool alias conflict for %q: proxy %q maps to %s, already mapped to %s", tool.Name, proxyID, derivedToolSourceIdentityForMessage(tool), derivedToolSourceIdentityForMessage(existing))
				}
				continue
			}
			byName[tool.Name] = tool
		}
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	tools := make([]oas.DerivedTool, 0, len(names))
	for _, name := range names {
		tools = append(tools, byName[name])
	}
	return tools, nil
}

func derivedToolSourceIdentity(tool oas.DerivedTool) string {
	if tool.SourceKey != "" {
		return tool.SourceKey
	}
	if tool.OperationID != "" {
		return "operationId:" + tool.OperationID
	}
	return tool.Name
}

func derivedToolSourceIdentityForMessage(tool oas.DerivedTool) string {
	if tool.OperationID != "" {
		return fmt.Sprintf("operationId %q", tool.OperationID)
	}
	if tool.SourceKey != "" {
		return fmt.Sprintf("source %q", tool.SourceKey)
	}
	return fmt.Sprintf("tool %q", tool.Name)
}

func logMCPAdapterDeriveWarnings(restAPIID string, warnings []oas.DeriveWarning) {
	for _, w := range warnings {
		mainLog.WithFields(map[string]interface{}{
			"rest_api_id": restAPIID,
			"operation":   w.Operation,
			"method":      w.Method,
			"path":        w.Path,
			"reason":      w.Reason,
		}).Warnf("MCP tool derivation warning: %s", w.Reason)
	}
}

func (gw *Gateway) newSyntheticMCPAdapterSpec(rest *APISpec, catalogue mcpAdapterCatalogue) *APISpec {
	cloned := *rest.APIDefinition
	cloned.APIID = oas.AdapterAPIID(rest.APIID)
	cloned.Name = rest.Name + " [MCP adapter]"
	cloned.Internal = true
	cloned.MarkAsMCP()
	cloned.Proxy.ListenPath = mcpAdapterListenPathPrefix + rest.APIID + "/"
	cloned.Proxy.TargetURL = "http://127.0.0.1/"
	cloned.UseKeylessAccess = true

	return &APISpec{
		APIDefinition:         &cloned,
		OAS:                   rest.OAS,
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       rest.APIID,
		DerivedPrimitives:     catalogue.primitives,
		DerivedTools:          catalogue.tools,
		MCPProxyToolViews:     catalogue.proxyToolViews,
		GlobalConfig:          gw.GetConfig(),
	}
}

func (gw *Gateway) attachSyntheticMCPAdapterRuntime(adapter *APISpec, tools []oas.DerivedTool) error {
	sdkAdapter, err := gw.buildOrUpdateMCPSDKAdapter(adapter, tools)
	if err != nil {
		return fmt.Errorf("build SDK adapter: %w", err)
	}
	adapter.MCPSDKAdapter = sdkAdapter
	adapter.Health = &DefaultHealthChecker{Gw: gw, APIID: adapter.APIID}
	adapter.AuthManager = &DefaultSessionManager{Gw: gw}
	adapter.OrgSessionManager = &DefaultSessionManager{orgID: adapter.OrgID, Gw: gw}
	return nil
}

func (gw *Gateway) buildOrUpdateMCPSDKAdapter(adapter *APISpec, tools []oas.DerivedTool) (*mcpadapter.SDKAdapter, error) {
	var existing *mcpadapter.SDKAdapter
	gw.apisMu.RLock()
	if cur := gw.apisByID[adapter.APIID]; cur != nil {
		existing = cur.MCPSDKAdapter
	}
	gw.apisMu.RUnlock()

	if existing != nil {
		if err := existing.UpdateCallTool(gw.mcpAdapterCallToolFunc(adapter)); err != nil {
			return nil, err
		}
		return existing, existing.UpdateTools(tools)
	}

	return mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:     adapter.Name,
		Tools:    tools,
		CallTool: gw.mcpAdapterCallToolFunc(adapter),
	})
}

func (gw *Gateway) mcpAdapterCallToolFunc(adapter *APISpec) mcpadapter.ToolCallFunc {
	return func(ctx context.Context, tool *oas.DerivedTool, args map[string]any) (*mcpadapter.Recorder, error) {
		return gw.callMCPAdapterTool(ctx, adapter, tool, args)
	}
}

func (gw *Gateway) callMCPAdapterTool(ctx context.Context, spec *APISpec, tool *oas.DerivedTool, args map[string]any) (*mcpadapter.Recorder, error) {
	if tool == nil {
		return nil, fmt.Errorf("nil tool")
	}
	parent, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
	if err != nil {
		return nil, err
	}

	if gw.mcpPairing == nil {
		return nil, fmt.Errorf("MCP pairing index is not initialised")
	}
	callerProxyAPIID := httpctx.MCPProxyCallerAPIIDFromContext(ctx)
	if callerProxyAPIID == "" {
		return nil, fmt.Errorf("caller proxy is not recorded for MCP adapter tool call")
	}
	if !gw.mcpPairing.ProxyAllowedForREST(spec.SourceRESTAPIID, callerProxyAPIID) {
		return nil, fmt.Errorf("caller proxy %q is not admitted for REST API %q", callerProxyAPIID, spec.SourceRESTAPIID)
	}

	resolvedTool, err := mcpAdapterToolForCaller(spec, callerProxyAPIID, tool)
	if err != nil {
		var notExposed *mcpToolNotExposedError
		if errors.As(err, &notExposed) {
			logMCPAdapterToolNotExposed(ctx, spec, notExposed)
		}
		return nil, err
	}

	upstreamReq, err := mcpadapter.BuildUpstreamRequest(parent, resolvedTool, spec.SourceRESTAPIID, args)
	if err != nil {
		return nil, err
	}

	httpctx.SetMCPLoopFromPairedProxy(upstreamReq, &httpctx.MCPLoopTrust{
		ProxyAPIID:   callerProxyAPIID,
		RESTAPIID:    spec.SourceRESTAPIID,
		AdapterAPIID: spec.APIID,
	})

	handler, _, ok := gw.findInternalHttpHandlerByNameOrID(exactMCPAPILoopTarget(spec.SourceRESTAPIID))
	if !ok {
		return nil, fmt.Errorf("paired REST API handler not found")
	}

	rec := mcpadapter.NewRecorder()
	handler.ServeHTTP(rec, upstreamReq)
	return rec, nil
}

func logMCPAdapterToolNotExposed(ctx context.Context, spec *APISpec, err *mcpToolNotExposedError) {
	if err == nil {
		return
	}

	fields := map[string]interface{}{
		"tool_name":    err.toolName,
		"proxy_api_id": err.proxyAPIID,
	}
	if spec != nil {
		fields["source_rest_api_id"] = spec.SourceRESTAPIID
		if spec.APIDefinition != nil {
			fields["adapter_api_id"] = spec.APIID
		}
	}
	if sessionKey := mcpAdapterSessionKeyFromContext(ctx); sessionKey != "" {
		fields["session_key"] = sessionKey
	}

	mainLog.WithFields(fields).Warn("MCP tool is not exposed for caller proxy")
}

func mcpAdapterSessionKeyFromContext(parent context.Context) string {
	if parent == nil {
		return ""
	}
	if session, ok := parent.Value(tykctx.SessionData).(*user.SessionState); ok && session != nil {
		return session.KeyID
	}
	if key, ok := parent.Value(tykctx.AuthToken).(string); ok {
		return key
	}
	return ""
}

func mcpAdapterToolForCaller(spec *APISpec, callerProxyAPIID string, requested *oas.DerivedTool) (*oas.DerivedTool, error) {
	if spec == nil {
		return nil, fmt.Errorf("nil adapter spec")
	}
	if requested == nil {
		return nil, fmt.Errorf("nil tool")
	}

	if spec.MCPProxyToolViews != nil {
		view, ok := spec.MCPProxyToolViews[callerProxyAPIID]
		if !ok {
			return nil, fmt.Errorf("caller proxy %q has no MCP tool view", callerProxyAPIID)
		}
		visibleTool, ok := view.ToolByName(requested.Name)
		if !ok {
			return nil, &mcpToolNotExposedError{toolName: requested.Name, proxyAPIID: callerProxyAPIID}
		}
		return canonicalMCPAdapterTool(visibleTool), nil
	}

	return canonicalMCPAdapterTool(*requested), nil
}

type mcpToolNotExposedError struct {
	toolName   string
	proxyAPIID string
}

func (e *mcpToolNotExposedError) Error() string {
	return fmt.Sprintf("tool %q is not exposed for caller proxy %q", e.toolName, e.proxyAPIID)
}

func canonicalMCPAdapterTool(tool oas.DerivedTool) *oas.DerivedTool {
	if tool.CanonicalName != "" {
		tool.Name = tool.CanonicalName
	}
	return &tool
}
