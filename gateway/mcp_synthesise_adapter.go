package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	mcpadapter "github.com/TykTechnologies/tyk/internal/mcp/adapter"
	mcppairing "github.com/TykTechnologies/tyk/internal/mcp/pairing"
)

// mcpAdapterListenPathPrefix is the listen path stem given to every
// synthesised adapter spec. Adapter specs are Internal so this path is
// never reachable from the public muxer; the prefix is only there to
// satisfy listen-path validation in loadHTTPService.
const mcpAdapterListenPathPrefix = "/__tyk-mcp-server/"

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
	specs []*APISpec,
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

		adapter, err := gw.buildAdapterSpec(rest)
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
		target := strings.TrimSpace(spec.Proxy.TargetURL)
		if target == "" {
			continue
		}
		u, err := url.Parse(target)
		if err != nil || u.Scheme != "tyk" {
			continue
		}
		adapterID := strings.TrimPrefix(u.Host, "id:")
		if !oas.IsAdapterAPIID(adapterID) {
			continue
		}
		restID := oas.AdapterSourceAPIID(adapterID)
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
	if rest == nil || rest.APIDefinition == nil {
		return nil, fmt.Errorf("nil source REST spec")
	}

	primitives, warns, err := oas.DeriveSourcePrimitives(&rest.OAS)
	if err != nil {
		return nil, fmt.Errorf("derive MCP primitives: %w", err)
	}
	for _, w := range warns {
		mainLog.WithFields(map[string]interface{}{
			"rest_api_id": rest.APIID,
			"operation":   w.Operation,
			"method":      w.Method,
			"path":        w.Path,
			"reason":      w.Reason,
		}).Warnf("MCP tool derivation warning: %s", w.Reason)
	}
	tools := oas.ToolPrimitives(primitives)

	adapterAPIID := oas.AdapterAPIID(rest.APIID)

	cloned := *rest.APIDefinition
	cloned.APIID = adapterAPIID
	cloned.Name = rest.Name + " [MCP adapter]"
	cloned.Internal = true
	cloned.MarkAsMCP()
	cloned.Proxy.ListenPath = mcpAdapterListenPathPrefix + rest.APIID + "/"
	cloned.Proxy.TargetURL = "http://127.0.0.1/"
	cloned.UseKeylessAccess = true

	adapter := &APISpec{
		APIDefinition:         &cloned,
		OAS:                   rest.OAS,
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       rest.APIID,
		DerivedPrimitives:     primitives,
		DerivedTools:          tools,
		GlobalConfig:          gw.GetConfig(),
	}

	sdkAdapter, err := gw.buildOrUpdateMCPSDKAdapter(adapter, tools)
	if err != nil {
		return nil, fmt.Errorf("build SDK adapter: %w", err)
	}
	adapter.MCPSDKAdapter = sdkAdapter

	adapter.Health = &DefaultHealthChecker{Gw: gw, APIID: adapter.APIID}
	adapter.AuthManager = &DefaultSessionManager{Gw: gw}
	adapter.OrgSessionManager = &DefaultSessionManager{orgID: adapter.OrgID, Gw: gw}

	return adapter, nil
}

func (gw *Gateway) buildOrUpdateMCPSDKAdapter(adapter *APISpec, tools []oas.DerivedTool) (*mcpadapter.SDKAdapter, error) {
	var existing *mcpadapter.SDKAdapter
	gw.apisMu.RLock()
	if cur := gw.apisByID[adapter.APIID]; cur != nil {
		existing = cur.MCPSDKAdapter
	}
	gw.apisMu.RUnlock()

	if existing != nil {
		return existing, existing.UpdateTools(tools)
	}

	return mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:  adapter.Name,
		Tools: tools,
		CallTool: func(ctx context.Context, tool *oas.DerivedTool, args map[string]any) (*mcpadapter.Recorder, error) {
			return gw.callMCPAdapterTool(ctx, adapter, tool, args)
		},
	})
}

func (gw *Gateway) callMCPAdapterTool(ctx context.Context, spec *APISpec, tool *oas.DerivedTool, args map[string]any) (*mcpadapter.Recorder, error) {
	parent, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
	if err != nil {
		return nil, err
	}
	upstreamReq, err := mcpadapter.BuildUpstreamRequest(parent, tool, spec.SourceRESTAPIID, args)
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

	httpctx.SetMCPLoopFromPairedProxy(upstreamReq, &httpctx.MCPLoopTrust{
		ProxyAPIID:   callerProxyAPIID,
		RESTAPIID:    spec.SourceRESTAPIID,
		AdapterAPIID: spec.APIID,
	})

	handler, _, ok := gw.findInternalHttpHandlerByNameOrID(spec.SourceRESTAPIID)
	if !ok {
		return nil, fmt.Errorf("paired REST API handler not found")
	}

	rec := mcpadapter.NewRecorder()
	handler.ServeHTTP(rec, upstreamReq)
	return rec, nil
}
