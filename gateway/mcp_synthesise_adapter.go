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
const mcpAdapterListenPathPrefix = "/__tyk-mcp-server/"

// synthesiseMCPAdapters walks the loaded REST APISpec set and, for every
// spec whose OAS marker `server.mcp.enabled: true` is set, emits a paired
// Internal adapter APISpec into tmpSpecRegister and tmpSpecHandles.
//
// Adapter specs:
//   - have deterministic APIID `<rest-apiid>__mcp-server`
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

// rebuildMCPPairing walks the in-flight spec register and replaces the
// pairing index (gw.mcpPairing) atomically with fresh REST→proxy and
// REST→adapter maps.
//
// A proxy is recognised by:
//   - Proxy.TargetURL has scheme `tyk` and host equal to an adapter
//     APIID registered in tmpSpecRegister
//   - The candidate is not itself a synthetic adapter
//   - REST/proxy OrgIDs match (cross-org targeting is refused; the
//     admit-time validator should already have caught it, this is
//     defence in depth)
//
// The 1:1 invariant is enforced at admit time by validateMCP; this
// rebuilder simply records the latest-wins pairing if it ever sees a
// duplicate.
func (gw *Gateway) rebuildMCPPairing(tmpSpecRegister map[string]*APISpec) {
	pairingMap, adapterMap := computeMCPPairing(tmpSpecRegister)
	gw.mcpPairing.Set(pairingMap, adapterMap)
}

// computeMCPPairing is the pure (gateway-free) core of
// rebuildMCPPairing — exported within the package for unit testing.
// Returns (restID→proxyID, restID→adapterID).
func computeMCPPairing(specs map[string]*APISpec) (pairing, adapter map[string]string) {
	pairing = map[string]string{}
	adapter = map[string]string{}

	for _, spec := range specs {
		if spec == nil || spec.APIDefinition == nil {
			continue
		}
		if spec.IsSyntheticMCPAdapter {
			// Record the adapter→REST mapping (key is the REST APIID).
			adapter[spec.SourceRESTAPIID] = spec.APIID
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
		pairing[restID] = spec.APIID
	}
	return pairing, adapter
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

	cloned := *rest.APIDefinition
	cloned.APIID = adapterAPIID
	cloned.Name = rest.Name + " [MCP adapter]"
	cloned.Internal = true
	cloned.MarkAsMCP()
	cloned.Proxy.ListenPath = mcpAdapterListenPathPrefix + rest.APIID + "/"
	cloned.Proxy.TargetURL = "http://127.0.0.1/"
	cloned.MCPExposure = apidef.MCPExposureConfig{}
	cloned.UseKeylessAccess = true

	adapter := &APISpec{
		APIDefinition:         &cloned,
		OAS:                   rest.OAS,
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       rest.APIID,
		DerivedTools:          tools,
		GlobalConfig:          gw.GetConfig(),
	}

	adapter.Health = &DefaultHealthChecker{Gw: gw, APIID: adapter.APIID}
	adapter.AuthManager = &DefaultSessionManager{Gw: gw}
	adapter.OrgSessionManager = &DefaultSessionManager{orgID: adapter.OrgID, Gw: gw}

	return adapter, nil
}
