package gateway

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
)

// mcpAdapterListenPathPrefix is the listen path stem given to every
// synthesised adapter spec. Adapter specs are Internal so this path is
// never reachable from the public muxer; the prefix is only there to
// satisfy listen-path validation in loadHTTPService.
const mcpAdapterListenPathPrefix = "/__tyk-mcp-adapter/"

// synthesiseMCPAdapters walks the loaded REST APISpec set and, for every
// spec whose OAS marker `server.mcp.enabled: true` is set, emits a paired
// Internal adapter APISpec into tmpSpecRegister and tmpSpecHandles.
//
// Adapter specs:
//   - have deterministic APIID `<rest-apiid>__mcp-adapter`
//   - inherit OrgID from the source REST spec (multi-tenant safety)
//   - are Internal:true (skipped by the public muxer per api_loader.go:196)
//   - are MarkedAsMCP() so JSONRPCMiddleware wires into the chain
//   - carry a fresh DerivedTools slice produced from the REST OAS via
//     oas.DeriveSourceTools — pure, gateway-agnostic, run on every reload
//
// The function is best-effort per spec: if derivation fails for one
// source REST API, the error is logged and the loader continues.
//
// Returns the synthesised specs (caller registers them) — they are also
// recorded in gw.mcpAdapter[restID] = adapterID.
func (gw *Gateway) synthesiseMCPAdapters(
	specs []*APISpec,
	tmpSpecRegister map[string]*APISpec,
	tmpSpecHandles *sync.Map,
	apisByListen map[string]int,
	gs *generalStores,
	muxer *proxyMux,
) []*APISpec {
	adapterMap := map[string]string{}
	var synthesised []*APISpec

	for _, rest := range specs {
		if rest == nil || rest.APIDefinition == nil {
			continue
		}
		if !rest.APIDefinition.IsMCPExposed() {
			continue
		}

		adapter, err := gw.buildAdapterSpec(rest)
		if err != nil {
			mainLog.WithError(err).WithField("rest_api_id", rest.APIID).
				Error("failed to synthesise MCP adapter spec")
			continue
		}
		mainLog.WithFields(map[string]interface{}{
			"rest_api_id":    rest.APIID,
			"adapter_api_id": adapter.APIID,
			"derived_count":  len(adapter.DerivedTools),
		}).Debug("synthesised MCP adapter")

		// Register in the in-flight maps so the rest of loadApps treats it
		// like any other spec for lookup purposes.
		tmpSpecRegister[adapter.APIID] = adapter

		handle, err := gw.loadHTTPService(adapter, apisByListen, gs, muxer)
		if err != nil {
			mainLog.WithError(err).WithField("adapter_api_id", adapter.APIID).
				Error("failed to load synthetic MCP adapter chain")
			delete(tmpSpecRegister, adapter.APIID)
			continue
		}
		tmpSpecHandles.Store(adapter.APIID, handle)

		adapterMap[rest.APIID] = adapter.APIID
		synthesised = append(synthesised, adapter)
	}

	// Index update is delayed until after the public-spec loop so callers
	// have the final view. Held under apisMu by the caller.
	gw.mcpAdapter = adapterMap

	return synthesised
}

// rebuildMCPPairing walks the in-flight spec register after both the
// public-spec load and synthetic-adapter synthesis have completed, and
// builds gw.mcpPairing — the restAPIID → proxyAPIID index used by
// MCPLoopAuthBypass and validateMCP.
//
// A proxy is recognised by:
//   - IsMCP() (operator marked it via /tyk/mcps)
//   - Proxy.TargetURL has scheme `tyk` and host equal to an adapter APIID
//     registered in tmpSpecRegister whose source REST API is in the same
//     OrgID.
//
// The 1:1 invariant (each adapter targeted by at most one proxy) is
// enforced at admit time by validateMCP; this rebuilder simply records
// the latest-wins pairing if it ever encounters a duplicate.
func (gw *Gateway) rebuildMCPPairing(tmpSpecRegister map[string]*APISpec) {
	pairing := map[string]string{}

	for _, spec := range tmpSpecRegister {
		if spec == nil || spec.APIDefinition == nil {
			continue
		}
		// Adapter specs target REST APIs; do not consider them as
		// proxies even though they share a tyk:// upstream shape.
		if spec.IsSyntheticMCPAdapter {
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
		adapter, ok := tmpSpecRegister[adapterID]
		rest, restOK := tmpSpecRegister[restID]
		if !ok || !restOK || adapter == nil || rest == nil {
			continue
		}
		if rest.OrgID != spec.OrgID {
			// Cross-org targeting — refuse to pair. validateMCP rejects
			// this at admit time but we double-check at runtime as
			// defence in depth.
			continue
		}
		pairing[restID] = spec.APIID
	}

	gw.mcpPairing = pairing
}

// buildAdapterSpec constructs an in-memory adapter APISpec paired with
// the given REST APISpec. The returned spec is ready to be passed to
// loadHTTPService — no further mutation is required.
func (gw *Gateway) buildAdapterSpec(rest *APISpec) (*APISpec, error) {
	if rest == nil || rest.APIDefinition == nil {
		return nil, fmt.Errorf("nil source REST spec")
	}

	var curation oas.MCPPrimitives
	if ext := rest.OAS.GetTykExtension(); ext != nil && ext.Middleware != nil {
		curation = ext.Middleware.McpTools
	}

	tools, warns, err := oas.DeriveSourceTools(&rest.OAS, curation)
	if err != nil {
		return nil, fmt.Errorf("derive tools: %w", err)
	}
	for _, w := range warns {
		mainLog.WithFields(map[string]interface{}{
			"rest_api_id": rest.APIID,
			"operation":   w.Operation,
		}).Warnf("MCP tool derivation warning: %s", w.Reason)
	}

	adapterAPIID := oas.AdapterAPIID(rest.APIID)

	// Shallow-clone the source apidef so we don't share mutable state
	// (specifically Proxy / VersionData / ExtendedPaths) with the REST
	// spec. The fields we explicitly overwrite below are the ones that
	// matter for adapter behaviour.
	cloned := *rest.APIDefinition
	cloned.APIID = adapterAPIID
	cloned.Name = rest.Name + " [MCP adapter]"
	cloned.Internal = true
	cloned.MarkAsMCP()
	// Listening path is never reachable (Internal:true), but
	// loadHTTPService validates it as well-formed.
	cloned.Proxy.ListenPath = mcpAdapterListenPathPrefix + rest.APIID + "/"
	cloned.Proxy.TargetURL = "http://127.0.0.1/" // placeholder; chain short-circuits
	// Reset the MCP exposure marker on the adapter — adapters are
	// callees, not source REST APIs.
	cloned.MCPExposure = apidef.MCPExposureConfig{}
	// Make sure the adapter is keyless from the proxy's point of view —
	// authentication happens at the operator-managed proxy in front, the
	// adapter only ever receives in-process loop traffic.
	cloned.UseKeylessAccess = true

	adapter := &APISpec{
		APIDefinition: &cloned,
		// Carry the same OAS by reference — the adapter middleware reads
		// the path/operation table to translate tools/call.
		OAS:                   rest.OAS,
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       rest.APIID,
		DerivedTools:          tools,
		GlobalConfig:          gw.GetConfig(),
	}

	// Initialise the same managers that MakeSpec installs on real
	// specs. processSpec → APISpec.Init dereferences these later, so a
	// nil here panics during loadHTTPService.
	adapter.Health = &DefaultHealthChecker{Gw: gw, APIID: adapter.APIID}
	adapter.AuthManager = &DefaultSessionManager{Gw: gw}
	adapter.OrgSessionManager = &DefaultSessionManager{orgID: adapter.OrgID, Gw: gw}

	return adapter, nil
}
