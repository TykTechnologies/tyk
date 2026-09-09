package gateway

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
	restmcpadapter "github.com/TykTechnologies/tyk/internal/mcp/adapter"
	"github.com/TykTechnologies/tyk/internal/mcp/pairing"
)

type mcpAdapterCatalogue struct {
	unionTools []oas.DerivedTool
	toolViews  map[string]oas.MCPToolView
}

type mcpPairingSynthesisAnalysis struct {
	snapshot        pairing.Snapshot
	sourcesByID     map[string]*APISpec
	proxiesByRESTID map[string][]*APISpec
}

type pendingMCPProxyPairing struct {
	spec      *APISpec
	restAPIID string
}

func synthesizeMCPAdapterSpecs(specs []*APISpec, existing map[string]*APISpec) ([]*APISpec, pairing.Snapshot, error) {
	analysis, err := analyzeMCPPairingsForSynthesis(specs)
	if err != nil {
		return specs, pairing.Snapshot{}, err
	}

	out := append([]*APISpec(nil), specs...)
	for _, restID := range analysis.snapshot.ReferencedRESTAPIIDs() {
		source := analysis.sourcesByID[restID]
		if source == nil {
			return specs, pairing.Snapshot{}, fmt.Errorf("paired REST API %q is not loaded", restID)
		}

		adapterID := pairing.CanonicalAdapterAPIID(restID)
		var existingAdapter *APISpec
		if existing != nil {
			existingAdapter = existing[adapterID]
		}

		adapterSpec, err := buildMCPAdapterSpec(source, analysis.proxiesByRESTID[restID], existingAdapter)
		if err != nil {
			return specs, pairing.Snapshot{}, err
		}
		out = append(out, adapterSpec)
	}

	return out, analysis.snapshot, nil
}

func (gw *Gateway) currentSyntheticMCPAdapterSpecs() map[string]*APISpec {
	out := map[string]*APISpec{}
	if gw == nil {
		return out
	}

	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()

	for apiID, spec := range gw.apisByID {
		if spec != nil && spec.IsSyntheticMCPAdapter() {
			out[apiID] = spec
		}
	}
	return out
}

func (gw *Gateway) findInternalHTTPHandlerForLoop(apiNameOrID string, caller *APISpec, r *http.Request) (handler http.Handler, targetAPI *APISpec, ok bool) {
	targetName := apiNameOrID
	if caller != nil && caller.APIDefinition != nil && caller.IsPairedMCPAdapterProxy() {
		if _, restAPIID, paired := pairedMCPAdapterTarget(caller.Proxy.TargetURL); paired {
			targetName = pairing.CanonicalAdapterAPIID(restAPIID)
			if r != nil {
				ctxSetMCPAdapterCallerProxyID(r, caller.APIID)
			}
		}
	}
	return gw.findInternalHttpHandlerByNameOrID(targetName)
}

func computeMCPPairing(specs []*APISpec) (pairing.Snapshot, error) {
	analysis, err := analyzeMCPPairingsForSynthesis(specs)
	if err != nil {
		return pairing.Snapshot{}, err
	}
	return analysis.snapshot, nil
}

func analyzeMCPPairingsForSynthesis(specs []*APISpec) (mcpPairingSynthesisAnalysis, error) {
	analysis := mcpPairingSynthesisAnalysis{
		sourcesByID:     make(map[string]*APISpec, len(specs)),
		proxiesByRESTID: map[string][]*APISpec{},
	}
	pairedProxies := make([]pendingMCPProxyPairing, 0)

	for _, spec := range specs {
		if spec == nil || spec.APIDefinition == nil || spec.IsSyntheticMCPAdapter() {
			continue
		}
		analysis.sourcesByID[spec.APIID] = spec

		if !spec.IsPairedMCPAdapterProxy() {
			continue
		}
		_, restAPIID, ok := pairedMCPAdapterTarget(spec.Proxy.TargetURL)
		if ok {
			pairedProxies = append(pairedProxies, pendingMCPProxyPairing{spec: spec, restAPIID: restAPIID})
			analysis.proxiesByRESTID[restAPIID] = append(analysis.proxiesByRESTID[restAPIID], spec)
		}
	}

	records := make([]pairing.Record, 0, len(pairedProxies))
	for _, paired := range pairedProxies {
		source := analysis.sourcesByID[paired.restAPIID]
		if source == nil || source.APIDefinition == nil {
			return mcpPairingSynthesisAnalysis{}, fmt.Errorf("paired REST API %q is not loaded", paired.restAPIID)
		}
		if !source.IsOAS {
			return mcpPairingSynthesisAnalysis{}, fmt.Errorf("paired REST API %q is a Classic API; REST-as-MCP sources must be Tyk OAS APIs", paired.restAPIID)
		}

		records = append(records, pairing.Record{
			SourceRESTAPIID:  paired.restAPIID,
			SourceOrgID:      source.OrgID,
			CallerProxyAPIID: paired.spec.APIID,
			CallerProxyOrgID: paired.spec.OrgID,
		})
	}

	for _, proxies := range analysis.proxiesByRESTID {
		sort.Slice(proxies, func(i, j int) bool { return proxies[i].APIID < proxies[j].APIID })
	}

	snapshot, err := pairing.NewSnapshot(records)
	if err != nil {
		return mcpPairingSynthesisAnalysis{}, err
	}
	analysis.snapshot = snapshot
	return analysis, nil
}

func buildMCPAdapterSpec(rest *APISpec, proxies []*APISpec, existing *APISpec) (*APISpec, error) {
	if rest == nil || rest.APIDefinition == nil {
		return nil, fmt.Errorf("REST-as-MCP source spec is nil")
	}
	catalogue, err := deriveMCPAdapterCatalogue(rest, proxies)
	if err != nil {
		return nil, err
	}

	adapterID := pairing.CanonicalAdapterAPIID(rest.APIID)
	gw := gatewayForSyntheticAdapter(rest, existing)
	sdkAdapter := (*restmcpadapter.SDKAdapter)(nil)
	if existing != nil {
		sdkAdapter = existing.MCPAdapter.SDKAdapter
	}
	if sdkAdapter == nil {
		sdkAdapter, err = restmcpadapter.NewSDKAdapter(restmcpadapter.SDKServerConfig{
			Name:     adapterID,
			Version:  "1.0",
			Tools:    catalogue.unionTools,
			CallTool: defaultMCPAdapterCallTool,
		})
		if err != nil {
			return nil, err
		}
	} else {
		if err := sdkAdapter.UpdateCallTool(defaultMCPAdapterCallTool); err != nil {
			return nil, err
		}
		if err := sdkAdapter.UpdateTools(catalogue.unionTools); err != nil {
			return nil, err
		}
	}

	allowedCallers := callerProxyIDs(proxies)
	adapterVersion := apidef.VersionInfo{UseExtendedPaths: true}
	adapterDef := &apidef.APIDefinition{
		APIID:    adapterID,
		Name:     adapterID,
		OrgID:    rest.OrgID,
		Active:   true,
		IsOAS:    true,
		Internal: true,
		// The hidden adapter is only reachable through paired MCP proxies.
		// Caller-facing auth and policies are enforced on those proxies.
		UseKeylessAccess: true,
		VersionData: apidef.VersionData{
			NotVersioned: true,
			Versions: map[string]apidef.VersionInfo{
				"": adapterVersion,
			},
		},
		Proxy: apidef.ProxyConfig{
			ListenPath: "/" + adapterID + "/",
			TargetURL:  "http://127.0.0.1",
		},
	}
	adapterDef.MarkAsMCP()

	doc := oas.OAS{T: openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: adapterID, Version: "1.0.0"},
		Paths: openapi3.NewPaths(
			openapi3.WithPath(oas.AdapterLoopPath, &openapi3.PathItem{
				Post: &openapi3.Operation{OperationID: "mcp"},
			}),
		),
	}}
	doc.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			ID:    adapterID,
			OrgID: rest.OrgID,
			Name:  adapterID,
			State: oas.State{Active: true},
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: "/" + adapterID + "/"},
		},
		Upstream: oas.Upstream{URL: "http://127.0.0.1"},
	})

	return &APISpec{
		APIDefinition: adapterDef,
		OAS:           doc,
		Health: &DefaultHealthChecker{
			Gw:    gw,
			APIID: adapterID,
		},
		RxPaths: map[string][]URLSpec{
			adapterVersion.Name: {},
		},
		WhiteListEnabled: map[string]bool{
			adapterVersion.Name: false,
		},
		AuthManager: &DefaultSessionManager{Gw: gw},
		OrgSessionManager: &DefaultSessionManager{
			orgID: rest.OrgID,
			Gw:    gw,
		},
		GlobalConfig: rest.GlobalConfig,
		MCPAdapter: MCPAdapterRuntime{
			Synthetic:                true,
			SourceRESTAPIID:          rest.APIID,
			SDKAdapter:               sdkAdapter,
			AllowedCallerProxyAPIIDs: allowedCallers,
			ToolViews:                catalogue.toolViews,
			UnionTools:               append([]oas.DerivedTool(nil), catalogue.unionTools...),
		},
		JSONRPCRouter: mcp.NewRouter(),
	}, nil
}

func gatewayForSyntheticAdapter(specs ...*APISpec) *Gateway {
	for _, spec := range specs {
		if spec == nil {
			continue
		}
		if manager, ok := spec.AuthManager.(*DefaultSessionManager); ok && manager.Gw != nil {
			return manager.Gw
		}
		if manager, ok := spec.OrgSessionManager.(*DefaultSessionManager); ok && manager.Gw != nil {
			return manager.Gw
		}
		if health, ok := spec.Health.(*DefaultHealthChecker); ok && health.Gw != nil {
			return health.Gw
		}
	}
	return nil
}

func deriveMCPAdapterCatalogue(rest *APISpec, proxies []*APISpec) (mcpAdapterCatalogue, error) {
	if rest == nil {
		return mcpAdapterCatalogue{}, fmt.Errorf("REST-as-MCP source spec is nil")
	}

	unionByName := map[string]oas.DerivedTool{}
	toolViews := make(map[string]oas.MCPToolView, len(proxies))

	for _, proxy := range proxies {
		if proxy == nil || proxy.APIDefinition == nil {
			continue
		}
		view, warnings, err := oas.DeriveMCPToolView(&rest.OAS, proxy.OAS.GetTykMCPServerExtension())
		logMCPDeriveWarnings(proxy.APIID, rest.APIID, warnings)
		if err != nil {
			return mcpAdapterCatalogue{}, fmt.Errorf("build MCP tool view for proxy %q: %w", proxy.APIID, err)
		}

		toolViews[proxy.APIID] = view
		for _, tool := range view.Tools {
			existing, duplicate := unionByName[tool.Name]
			if duplicate && derivedToolSourceIdentity(existing) != derivedToolSourceIdentity(tool) {
				return mcpAdapterCatalogue{}, fmt.Errorf("MCP tool alias conflict for %q: sources %q and %q", tool.Name, derivedToolSourceIdentity(existing), derivedToolSourceIdentity(tool))
			}
			unionByName[tool.Name] = tool
		}
	}

	unionTools := make([]oas.DerivedTool, 0, len(unionByName))
	for _, tool := range unionByName {
		unionTools = append(unionTools, tool)
	}
	sort.Slice(unionTools, func(i, j int) bool { return unionTools[i].Name < unionTools[j].Name })

	return mcpAdapterCatalogue{
		unionTools: unionTools,
		toolViews:  toolViews,
	}, nil
}

func (gw *Gateway) pairedMCPProxyIDsReferencingRESTSource(restAPIID string) []string {
	if gw == nil || restAPIID == "" {
		return nil
	}

	source, ok := gw.mcpPairingIndex.LookupSource(restAPIID)
	if !ok {
		return nil
	}
	return source.CallerProxyAPIIDs
}

func callerProxyIDs(proxies []*APISpec) []string {
	ids := make([]string, 0, len(proxies))
	for _, proxy := range proxies {
		if proxy != nil && proxy.APIID != "" {
			ids = append(ids, proxy.APIID)
		}
	}
	sort.Strings(ids)
	return ids
}

func defaultMCPAdapterCallTool(ctx context.Context, tool *oas.DerivedTool, args map[string]any) (*restmcpadapter.Recorder, error) {
	gw := mcpAdapterGatewayFromContext(ctx)
	adapterSpec := mcpAdapterSpecFromContext(ctx)
	parentReq := mcpAdapterParentRequestFromContext(ctx)
	if gw == nil || adapterSpec == nil || parentReq == nil {
		return nil, fmt.Errorf("REST-as-MCP adapter callback is not installed")
	}
	return gw.callMCPAdapterTool(parentReq, adapterSpec, tool, args)
}

func (gw *Gateway) callMCPAdapterTool(parentReq *http.Request, adapterSpec *APISpec, tool *oas.DerivedTool, args map[string]any) (*restmcpadapter.Recorder, error) {
	if gw == nil {
		return nil, fmt.Errorf("gateway is nil")
	}
	if parentReq == nil {
		return nil, fmt.Errorf("REST-as-MCP parent request is nil")
	}
	if adapterSpec == nil || !adapterSpec.IsSyntheticMCPAdapter() {
		return nil, fmt.Errorf("REST-as-MCP adapter spec is invalid")
	}
	if tool == nil {
		return nil, fmt.Errorf("REST-as-MCP tool is nil")
	}

	callerProxyID := ctxGetMCPAdapterCallerProxyID(parentReq)
	if callerProxyID == "" {
		return nil, fmt.Errorf("caller proxy is required")
	}
	if !gw.mcpPairingIndex.AllowsCaller(adapterSpec.APIID, callerProxyID) {
		return nil, fmt.Errorf("caller proxy is not allowed for REST-as-MCP adapter")
	}

	view, ok := adapterSpec.MCPAdapter.ToolViews[callerProxyID]
	if !ok {
		return nil, fmt.Errorf("caller proxy has no REST-as-MCP tool view")
	}
	callerTool, ok := view.ToolByName(tool.Name)
	if !ok {
		logMCPToolHiddenFromCaller(adapterSpec, callerProxyID, tool.Name)
		return nil, fmt.Errorf("tool not found")
	}

	sourceRESTAPIID := adapterSpec.MCPAdapter.SourceRESTAPIID
	upstreamReq, err := restmcpadapter.BuildUpstreamRequest(parentReq, &callerTool, sourceRESTAPIID, args)
	if err != nil {
		return nil, err
	}
	ctxSetMCPAdapterLoopTrust(upstreamReq, mcpAdapterLoopTrust{
		SourceRESTAPIID:  sourceRESTAPIID,
		AdapterAPIID:     adapterSpec.APIID,
		CallerProxyAPIID: callerProxyID,
	})

	handler, _, ok := gw.findInternalHttpHandlerByNameOrID(sourceRESTAPIID)
	if !ok {
		return nil, fmt.Errorf("source REST API %q handler not found", sourceRESTAPIID)
	}

	rec := restmcpadapter.NewRecorder()
	handler.ServeHTTP(rec, upstreamReq)
	return rec, nil
}

func logMCPToolHiddenFromCaller(adapterSpec *APISpec, callerProxyID, toolName string) {
	log.WithFields(logrus.Fields{
		"tool_name":          toolName,
		"proxy_api_id":       callerProxyID,
		"source_rest_api_id": adapterSpec.MCPAdapter.SourceRESTAPIID,
		"adapter_api_id":     adapterSpec.APIID,
	}).Warn("MCP tool is not exposed for caller proxy")
}
