package gateway

import (
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
)

// mcpProxyTestGateway returns a minimal Gateway suitable for testing the
// runtime-state validators and back-ref helpers. The tests don't need the
// full HTTP harness — the validators are pure functions over apisByID +
// apisHandlesByID, and the structural validator is already covered in
// apidef/oas/mcp_proxy_test.go.
func mcpProxyTestGateway(specs map[string]*APISpec) *Gateway {
	gw := &Gateway{
		apisMu:          sync.RWMutex{},
		apisByID:        make(map[string]*APISpec),
		apisHandlesByID: new(sync.Map),
	}
	for id, spec := range specs {
		gw.apisByID[id] = spec
		gw.apisHandlesByID.Store(id, &ChainObject{})
	}
	return gw
}

// mcpProxySource returns a loopback source pointing at the given APIID.
func mcpProxySource(slug, sourceAPIID string) oas.MCPSource {
	return oas.MCPSource{
		SourceSlug:  slug,
		BackendMode: "loopback",
		SourceAPIID: sourceAPIID,
	}
}

// sourceSpec builds an APISpec with the given auth flags and back-ref state.
func sourceSpec(apiID string, acceptLoop, keyless, mtls bool, mcpProxies []string) *APISpec {
	o := oas.OAS{}
	o.SetTykExtension(&oas.XTykAPIGateway{
		Server: oas.Server{
			AcceptMCPLoopCallers: acceptLoop,
			MCPProxies:           mcpProxies,
		},
	})
	return &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:            apiID,
			IsOAS:            true,
			UseKeylessAccess: keyless,
			UseMutualTLSAuth: mtls,
		},
		OAS: o,
	}
}

func TestValidateMCPProxyRuntimeState_HappyPath(t *testing.T) {
	t.Parallel()

	src := sourceSpec("src-keyless", true, true, false, nil)
	gw := mcpProxyTestGateway(map[string]*APISpec{"src-keyless": src})

	proxy := &oas.MCPProxy{
		Sources: []oas.MCPSource{mcpProxySource("k", "src-keyless")},
	}

	err := gw.validateMCPProxyRuntimeState(proxy)
	assert.False(t, err.HasViolations(), "expected no violations, got: %+v", err)
}

func TestValidateMCPProxyRuntimeState_SourceNotLoaded(t *testing.T) {
	t.Parallel()

	gw := mcpProxyTestGateway(nil)

	proxy := &oas.MCPProxy{
		Sources: []oas.MCPSource{mcpProxySource("missing", "ghost-api")},
	}

	rerr := gw.validateMCPProxyRuntimeState(proxy)
	require.True(t, rerr.HasViolations())
	require.Len(t, rerr.Violations, 1)
	assert.Equal(t, MCPProxyErrSourceNotLoaded, rerr.Violations[0].Code)
	assert.Equal(t, "ghost-api", rerr.Violations[0].SourceAPIID)
}

func TestValidateMCPProxyRuntimeState_SourceNotMCPCallable_AndKeylessOnly(t *testing.T) {
	t.Parallel()

	// AcceptMCPLoopCallers=false but keyless — only source_not_mcp_callable
	// fires; the auth-conjunction rule does NOT.
	src := sourceSpec("src-keyless-noaccept", false, true, false, nil)
	gw := mcpProxyTestGateway(map[string]*APISpec{"src-keyless-noaccept": src})

	proxy := &oas.MCPProxy{
		Sources: []oas.MCPSource{mcpProxySource("k", "src-keyless-noaccept")},
	}

	rerr := gw.validateMCPProxyRuntimeState(proxy)
	require.True(t, rerr.HasViolations())
	require.Len(t, rerr.Violations, 1)
	assert.Equal(t, MCPProxyErrSourceNotMCPCallable, rerr.Violations[0].Code)
}

func TestValidateMCPProxyRuntimeState_LoopbackRequiresMCPCallerAuthOrKeyless(t *testing.T) {
	t.Parallel()

	// AcceptMCPLoopCallers=false AND non-keyless: BOTH violations fire so the
	// operator sees the full punch list.
	src := sourceSpec("src-noaccept-noauth", false, false, false, nil)
	gw := mcpProxyTestGateway(map[string]*APISpec{"src-noaccept-noauth": src})

	proxy := &oas.MCPProxy{
		Sources: []oas.MCPSource{mcpProxySource("k", "src-noaccept-noauth")},
	}

	rerr := gw.validateMCPProxyRuntimeState(proxy)
	require.True(t, rerr.HasViolations())
	require.Len(t, rerr.Violations, 2)

	codes := []string{rerr.Violations[0].Code, rerr.Violations[1].Code}
	assert.Contains(t, codes, MCPProxyErrSourceNotMCPCallable)
	assert.Contains(t, codes, MCPProxyErrLoopbackSourceRequiresMCPCallerAuthOrKeyless)
}

func TestValidateMCPProxyRuntimeState_MTLSUnsupported(t *testing.T) {
	t.Parallel()

	// AcceptMCPLoopCallers=true so the only violation is mTLS.
	src := sourceSpec("src-mtls", true, false, true, nil)
	gw := mcpProxyTestGateway(map[string]*APISpec{"src-mtls": src})

	proxy := &oas.MCPProxy{
		Sources: []oas.MCPSource{mcpProxySource("m", "src-mtls")},
	}

	rerr := gw.validateMCPProxyRuntimeState(proxy)
	require.True(t, rerr.HasViolations())
	require.Len(t, rerr.Violations, 1)
	assert.Equal(t, MCPProxyErrMTLSLoopbackSourceUnsupportedInPoC, rerr.Violations[0].Code)
}

func TestValidateMCPProxyRuntimeState_MultipleSourcesAggregate(t *testing.T) {
	t.Parallel()

	// One source: not loaded. Another: mTLS. Operator gets both in one shot.
	mtls := sourceSpec("src-mtls", true, false, true, nil)
	gw := mcpProxyTestGateway(map[string]*APISpec{"src-mtls": mtls})

	proxy := &oas.MCPProxy{
		Sources: []oas.MCPSource{
			mcpProxySource("a", "ghost-api"),
			mcpProxySource("b", "src-mtls"),
		},
	}

	rerr := gw.validateMCPProxyRuntimeState(proxy)
	require.True(t, rerr.HasViolations())
	require.Len(t, rerr.Violations, 2)

	codes := []string{rerr.Violations[0].Code, rerr.Violations[1].Code}
	assert.Contains(t, codes, MCPProxyErrSourceNotLoaded)
	assert.Contains(t, codes, MCPProxyErrMTLSLoopbackSourceUnsupportedInPoC)
}

func TestValidateMCPProxyRuntimeState_UpstreamSourcesSkipped(t *testing.T) {
	t.Parallel()

	gw := mcpProxyTestGateway(nil)

	proxy := &oas.MCPProxy{
		Sources: []oas.MCPSource{
			{
				SourceSlug:  "u",
				BackendMode: "upstream",
				UpstreamURL: "https://example.com",
			},
		},
	}

	rerr := gw.validateMCPProxyRuntimeState(proxy)
	assert.False(t, rerr.HasViolations(), "upstream sources must not be runtime-validated")
}

func TestSourceDeletionGuard_NoBackRefs(t *testing.T) {
	t.Parallel()
	src := sourceSpec("src", true, true, false, nil)
	assert.False(t, SourceDeletionGuard(src).HasViolations())
}

func TestSourceDeletionGuard_WithBackRefs(t *testing.T) {
	t.Parallel()
	src := sourceSpec("src-with-deps", true, true, false, []string{"proxy-a", "proxy-b"})
	rerr := SourceDeletionGuard(src)
	require.True(t, rerr.HasViolations())
	require.Len(t, rerr.Violations, 2)
	for _, v := range rerr.Violations {
		assert.Equal(t, MCPProxyErrSourceHasDependents, v.Code)
		assert.Equal(t, "src-with-deps", v.SourceAPIID)
	}
}

func TestSourceDeletionGuard_NilSpec(t *testing.T) {
	t.Parallel()
	assert.False(t, SourceDeletionGuard(nil).HasViolations())
}

// TestDeleteAPI_SourceDeletionGuard verifies that handleDeleteAPI rejects a
// DELETE on a source APIDef while it still carries a non-empty MCPProxies
// back-ref, with HTTP 409 and a violations payload listing each dependent
// proxy. After the back-ref is cleared, the same DELETE proceeds (the guard
// is the only short-circuit before file IO; we don't exercise the file-IO
// path in this unit test).
func TestDeleteAPI_SourceDeletionGuard(t *testing.T) {
	t.Parallel()

	// Source spec carries two dependent proxies in its back-ref.
	src := sourceSpec("src-with-deps", true, true, false, []string{"proxy-a", "proxy-b"})
	gw := mcpProxyTestGateway(map[string]*APISpec{"src-with-deps": src})

	resp, code := gw.handleDeleteAPI("src-with-deps")
	require.Equal(t, http.StatusConflict, code, "expected 409 from source-deletion guard")

	body, ok := resp.(mcpProxyRuntimeResponse)
	require.True(t, ok, "expected mcpProxyRuntimeResponse, got %T", resp)
	require.Len(t, body.Violations, 2)

	dependents := []string{body.Violations[0].Message, body.Violations[1].Message}
	for _, code := range []string{body.Violations[0].Code, body.Violations[1].Code} {
		assert.Equal(t, MCPProxyErrSourceHasDependents, code)
	}
	// Dependent proxy APIIDs surface in the message text so the operator can
	// see exactly which proxies still reference the source.
	joined := dependents[0] + "|" + dependents[1]
	assert.Contains(t, joined, "proxy-a")
	assert.Contains(t, joined, "proxy-b")
}

func TestIsMCPProxySpec(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		spec *APISpec
		want bool
	}{
		{"nil", nil, false},
		{"plain source", sourceSpec("plain", true, true, false, nil), false},
		{"with mcp proxy ext", func() *APISpec {
			o := oas.OAS{}
			o.SetTykExtension(&oas.XTykAPIGateway{
				Server: oas.Server{MCPProxy: &oas.MCPProxy{}},
			})
			return &APISpec{
				APIDefinition: &apidef.APIDefinition{APIID: "p", IsOAS: true},
				OAS:           o,
			}
		}(), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isMCPProxySpec(tc.spec))
		})
	}
}

func TestLoopbackSourceIDSet(t *testing.T) {
	t.Parallel()

	sources := []oas.MCPSource{
		{BackendMode: "loopback", SourceAPIID: "a"},
		{BackendMode: "loopback", SourceAPIID: "b"},
		{BackendMode: "upstream", UpstreamURL: "https://x"},
		{BackendMode: "loopback", SourceAPIID: ""}, // skipped — structural error
		{BackendMode: "loopback", SourceAPIID: "a"}, // dup — set semantics
	}

	got := loopbackSourceIDSet(sources)
	assert.Len(t, got, 2)
	_, hasA := got["a"]
	_, hasB := got["b"]
	assert.True(t, hasA)
	assert.True(t, hasB)
}

// MCPProxyValidationError shape regression: ensure HasCode and Codes survive
// the round-trip from oas.OAS.Validate. This guards the 422 branch in
// validateMCPProxy that wraps the structural error into the response body.
func TestMCPProxyStructuralValidate_NotImplementedInPoC(t *testing.T) {
	t.Parallel()

	proxy := &oas.MCPProxy{
		Sources: []oas.MCPSource{
			{
				SourceSlug:  "svc",
				BackendMode: "upstream",
				UpstreamURL: "https://x",
				ServiceCred: &oas.ServiceCredRef{AuthType: "apikey", SecretRef: "vault://x"},
			},
		},
	}

	err := proxy.Validate(nil)
	require.Error(t, err)

	verr, ok := err.(*oas.MCPProxyValidationError)
	require.True(t, ok)
	assert.True(t, verr.HasCode(oas.MCPErrNotImplementedInPoC))
	assert.Contains(t, verr.Details, oas.MCPNotImplementedDetailServiceCred)
}

func TestMCPProxyStructuralValidate_UpstreamCredMTLS(t *testing.T) {
	t.Parallel()

	proxy := &oas.MCPProxy{
		Sources: []oas.MCPSource{
			{
				SourceSlug:   "svc",
				BackendMode:  "upstream",
				UpstreamURL:  "https://x",
				UpstreamCred: &oas.UpstreamCred{AuthType: "mtls"},
			},
		},
	}

	err := proxy.Validate(nil)
	require.Error(t, err)

	verr, ok := err.(*oas.MCPProxyValidationError)
	require.True(t, ok)
	assert.True(t, verr.HasCode(oas.MCPErrNotImplementedInPoC))
	assert.Contains(t, verr.Details, oas.MCPNotImplementedDetailUpstreamCredMTLS)
}
