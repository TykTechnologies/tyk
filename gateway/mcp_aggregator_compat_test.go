package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

// startMCPAggregatorCompatTest loads orders-mcp (an API-to-MCP proxy) and
// github-mcp (a remote MCP proxy over github) without any aggregator.
func startMCPAggregatorCompatTest(t *testing.T, githubURL string) *Test {
	t.Helper()
	ts, _, ordersBackend := startMCPAggregatorRuntimeTest(t)
	ts.Gw.LoadAPI(
		ordersRESTSourceSpec(ordersBackend.URL, false),
		ordersMCPProxyRuntimeSpec(),
		githubMCPProxyRuntimeSpec(githubURL),
	)
	return ts
}

func mcpAggregatorVersionCheckWarnings(hook interface{ AllEntries() []*logrus.Entry }, upstreamAPIID string) []*logrus.Entry {
	var out []*logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && entry.Message == mcpAggregatorVersionUncheckedMsg && entry.Data["upstream_api_id"] == upstreamAPIID {
			out = append(out, entry)
		}
	}
	return out
}

func TestMCPAggregatorAdmitsAggregatedProxiesServingTheLatestVersion(t *testing.T) {
	for name, github := range map[string]*mcpVersionedUpstream{
		"latest only": newLatestOnlyMCPUpstream(t, "list_issues"),
		"dual":        newDualMCPUpstream(t, "list_issues"),
	} {
		t.Run(name, func(t *testing.T) {
			ts := startMCPAggregatorCompatTest(t, github.URL)
			hook := log.GetTestHook(t)

			res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
				aggregated("orders-mcp", "orders"),
				aggregated("github-mcp", "github"),
			))

			require.Equal(t, http.StatusOK, res.code, res.body)
			assert.True(t, res.nextCalled)
			assert.Empty(t, mcpAggregatorVersionCheckWarnings(hook, "orders-mcp"), "the API-to-MCP proxy is checked and passes")
			assert.Empty(t, mcpAggregatorVersionCheckWarnings(hook, "github-mcp"))
			observed := github.observed()
			require.NotEmpty(t, observed, "github was probed")
			for _, req := range observed {
				assert.Equal(t, mcp.ModernProtocolVersion, req.HeaderVersion)
				assert.Equal(t, mcp.ModernProtocolVersion, req.MetaVersion)
			}
		})
	}
}

func TestMCPAggregatorRejectsAggregatedProxyWithoutTheLatestVersion(t *testing.T) {
	github := newLegacyOnlyMCPUpstream(t, "list_issues")
	ts := startMCPAggregatorCompatTest(t, github.URL)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		aggregated("orders-mcp", "orders"),
		aggregated("github-mcp", "github"),
	))

	assert.Equal(t, http.StatusBadRequest, res.code, res.body)
	assert.False(t, res.nextCalled)
	assert.Contains(t, res.body, `aggregated MCP proxy \"github-mcp\" does not support MCP version 2026-07-28`)
	assert.NotContains(t, res.body, "orders-mcp", "the API-to-MCP proxy passes the check")
}

func TestMCPAggregatorUpdateRejectsAddingAggregatedProxyWithoutTheLatestVersion(t *testing.T) {
	github := newLatestOnlyMCPUpstream(t, "list_issues")
	legacy := newLegacyOnlyMCPUpstream(t, "list_issues")
	ts := startMCPAggregatorCompatTest(t, github.URL)
	legacySpec := githubMCPProxyRuntimeSpec(legacy.URL)
	legacySpec.APIID, legacySpec.Name, legacySpec.Proxy.ListenPath = "legacy-mcp", "legacy-mcp", "/legacy-mcp/"
	ts.Gw.LoadAPI(
		githubMCPProxyRuntimeSpec(github.URL),
		legacySpec,
		companyToolsRuntimeSpec(aggregated("github-mcp", "github")),
	)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPut, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		aggregated("github-mcp", "github"),
		aggregated("legacy-mcp", "legacy"),
	))

	assert.Equal(t, http.StatusBadRequest, res.code, res.body)
	assert.Contains(t, res.body, `aggregated MCP proxy \"legacy-mcp\" does not support MCP version 2026-07-28`)
}

func TestHandleAddApiOASRejectsMCPAggregatorOverAggregatedProxyWithoutTheLatestVersion(t *testing.T) {
	ts := startMCPAggregatorCompatTest(t, newLegacyOnlyMCPUpstream(t, "list_issues").URL)

	body, err := json.Marshal(mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github")))
	require.NoError(t, err)
	resp, code := ts.Gw.handleAddApi(httptest.NewRequest(http.MethodPost, "/tyk/apis/oas", bytes.NewReader(body)), afero.NewMemMapFs(), true)

	require.Equal(t, http.StatusBadRequest, code)
	msg, ok := resp.(apiStatusMessage)
	require.True(t, ok)
	assert.Contains(t, msg.Message, `aggregated MCP proxy "github-mcp" does not support MCP version 2026-07-28`)
}

func TestMCPAggregatorAdmitsUnavailableAggregatedProxyWithAWarning(t *testing.T) {
	down := newLatestOnlyMCPUpstream(t, "list_issues")
	down.Close()
	ts := startMCPAggregatorCompatTest(t, down.URL)
	hook := log.GetTestHook(t)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		aggregated("orders-mcp", "orders"),
		aggregated("github-mcp", "github"),
	))

	require.Equal(t, http.StatusOK, res.code, res.body)
	assert.NotContains(t, res.body, "does not support MCP version")
	warnings := mcpAggregatorVersionCheckWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, "company-tools", warnings[0].Data["aggregator_api_id"])
	assert.NotContains(t, warnings[0].Data["reason"], "version mismatch")
	assert.Regexp(t, `^server/discover: .+; tools/list: .+`, warnings[0].Data["reason"], "both failed calls are reported")
	assert.Empty(t, mcpAggregatorVersionCheckWarnings(hook, "orders-mcp"))
}

func TestMCPAggregatorProbeTrustIsLimitedToReadOnlyDiscovery(t *testing.T) {
	gw := newMCPTestGateway(t)
	github := mcpManagedTestSpec("github-mcp")
	github.OrgID = mcpAggregatorRuntimeOrg
	mw := &MCPAggregatorLoopAuthBypassMiddleware{BaseMiddleware: &BaseMiddleware{Spec: github, Gw: gw}}

	process := func(method string, trust *mcpAggregatorLoopTrust) int {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctxSetMCPMethod(req, method)
		ctxSetMCPAggregatorLoopTrust(req, trust)
		_, code := mw.ProcessRequest(httptest.NewRecorder(), req, nil)
		return code
	}
	probe := func(org, upstream string) *mcpAggregatorLoopTrust {
		return &mcpAggregatorLoopTrust{OrgID: org, AggregatorAPIID: "company-tools", UpstreamAPIID: upstream, Probe: true}
	}

	assert.Equal(t, http.StatusOK, process(mcp.MethodServerDiscover, probe(mcpAggregatorRuntimeOrg, "github-mcp")))
	assert.Equal(t, http.StatusOK, process(mcp.MethodToolsList, probe(mcpAggregatorRuntimeOrg, "github-mcp")))
	assert.Equal(t, http.StatusForbidden, process(mcp.MethodToolsCall, probe(mcpAggregatorRuntimeOrg, "github-mcp")), "a probe never calls tools")
	assert.Equal(t, http.StatusForbidden, process(mcp.MethodServerDiscover, probe("globex", "github-mcp")))
	assert.Equal(t, http.StatusForbidden, process(mcp.MethodServerDiscover, probe(mcpAggregatorRuntimeOrg, "orders-mcp")))
}

func TestMCPAggregatorRejectsAggregatedProxyDiscoveringOnlyOlderVersions(t *testing.T) {
	github := newDualMCPUpstream(t, "list_issues")
	github.discoverVersions = []string{"2025-11-25"}
	ts := startMCPAggregatorCompatTest(t, github.URL)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github")))

	assert.Equal(t, http.StatusBadRequest, res.code, res.body)
	assert.Contains(t, res.body, `aggregated MCP proxy \"github-mcp\" does not support MCP version 2026-07-28: upstream supports only 2025-11-25`)
}

func TestMCPAggregatorVersionMismatchSignals(t *testing.T) {
	jsonHeader := http.Header{headerContentType: {contentTypeJSON}}
	for name, tc := range map[string]struct {
		status int
		header http.Header
		body   string
		want   string
	}{
		"gateway unsupported version error": {
			http.StatusBadRequest, jsonHeader,
			`{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported protocol version","data":{"requested":"2026-07-28","supported":["2025-03-26"]}}}`,
			"upstream rejected it: unsupported protocol version (supported: 2025-03-26)",
		},
		"SDK error in an event stream": {
			http.StatusOK, http.Header{headerContentType: {"text/event-stream"}},
			"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"Bad Request: Unsupported protocol version: 2026-07-28\"}}\n\n",
			"upstream rejected it: Bad Request: Unsupported protocol version: 2026-07-28",
		},
		"SDK plain text HTTP 400": {
			http.StatusBadRequest, http.Header{headerContentType: {"text/plain"}},
			"Bad Request: Unsupported protocol version (supported versions: 2025-03-26)\n",
			"upstream rejected it: Bad Request: Unsupported protocol version (supported versions: 2025-03-26)",
		},
		"result declaring another version": {
			http.StatusOK, jsonHeader,
			`{"jsonrpc":"2.0","id":1,"result":{"tools":[],"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-03-26"}}}`,
			"upstream answered on 2025-03-26",
		},
		"response header declaring another version": {
			http.StatusOK, http.Header{headerContentType: {contentTypeJSON}, mcp.HeaderProtocolVersion: {"2025-03-26"}},
			`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`,
			"upstream answered on 2025-03-26",
		},
		"session required in plain text": {
			http.StatusBadRequest, http.Header{},
			"Bad Request: Mcp-Session-Id header is required",
			"upstream requires a legacy session: Bad Request: Mcp-Session-Id header is required",
		},
		"session required as a JSON-RPC error": {
			http.StatusBadRequest, jsonHeader,
			`{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: No valid session ID provided"},"id":null}`,
			"upstream requires a legacy session: Bad Request: No valid session ID provided",
		},
		"session not found on 404": {
			http.StatusNotFound, http.Header{}, "session not found",
			"upstream requires a legacy session: session not found",
		},
		"server not initialized": {
			http.StatusBadRequest, jsonHeader,
			`{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: Server not initialized"},"id":null}`,
			"upstream requires a legacy session: Bad Request: Server not initialized",
		},
		"Python missing session ID": {
			http.StatusBadRequest, jsonHeader,
			`{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: Missing session ID"},"id":null}`,
			"upstream requires a legacy session: Bad Request: Missing session ID",
		},
		"Go SDK request during session initialization": {
			http.StatusBadRequest, http.Header{headerContentType: {"text/plain"}},
			"method \"tools/list\" is invalid during session initialization\n",
			`upstream requires a legacy session: method "tools/list" is invalid during session initialization`,
		},
		"invalid session token from an auth layer": {
			http.StatusBadRequest, jsonHeader, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"invalid session token"}}`, "",
		},
		"expired application session on 404": {http.StatusNotFound, http.Header{headerContentType: {"text/plain"}}, "session expired, unknown user", ""},
		"modern result":                      {http.StatusOK, jsonHeader, `{"jsonrpc":"2.0","id":1,"result":{"tools":[],"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`, ""},
		"other JSON-RPC error":               {http.StatusOK, jsonHeader, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`, ""},
		"upstream unavailable":               {http.StatusBadGateway, http.Header{}, "", ""},
		"other plain text 400":               {http.StatusBadRequest, http.Header{}, "Bad Request: invalid JSON", ""},
		"session text on 500":                {http.StatusInternalServerError, http.Header{}, "session not found", ""},
		"unsupported text on 500":            {http.StatusInternalServerError, http.Header{}, "unsupported protocol version", ""},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, mcpAggregatorVersionMismatch(mcp.MethodToolsList, tc.status, tc.header, []byte(tc.body)))
			assert.Equal(t, tc.want, mcpAggregatorVersionMismatch(mcp.MethodServerDiscover, tc.status, tc.header, []byte(tc.body)))
		})
	}
}

func TestMCPAggregatorVersionTextSignalsApplyOnlyToDiscovery(t *testing.T) {
	jsonHeader := http.Header{headerContentType: {contentTypeJSON}}
	for name, body := range map[string]string{
		"tool error mentioning the version": `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Unsupported protocol version in the payload"}}`,
		"tool error mentioning a session":   `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Mcp-Session-Id header is required"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, mcpAggregatorVersionMismatch(mcp.MethodToolsCall, http.StatusBadRequest, jsonHeader, []byte(body)))
			assert.NotEmpty(t, mcpAggregatorVersionMismatch(mcp.MethodToolsList, http.StatusBadRequest, jsonHeader, []byte(body)))
		})
	}
	assert.NotEmpty(t, mcpAggregatorVersionMismatch(mcp.MethodToolsCall, http.StatusBadRequest, jsonHeader,
		[]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported protocol version"}}`)),
		"the -32022 code is structural and applies to every method")
}

// sessionFirstLegacyMCPUpstream is a stateful 2025-03-26 server that checks
// the session before the protocol version, as the TypeScript and Python SDKs
// do: a non-initialize request without a session gets HTTP 400.
func sessionFirstLegacyMCPUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method != mcp.MethodInitialize && r.Header.Get(mcp.HeaderSessionID) == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: Mcp-Session-Id header is required"},"id":null}`))
			return
		}
		w.Header().Set(mcp.HeaderSessionID, "legacy-session")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{
			"protocolVersion": mcp.LegacyFallbackProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
		}})
	}))
	t.Cleanup(s.Close)
	return s
}

// headerUnawareLegacyMCPUpstream is a stateless 2025-03-26 server that
// ignores Mcp-Protocol-Version and has no server/discover.
func headerUnawareLegacyMCPUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == mcp.MethodToolsList {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{
				"tools": []any{map[string]any{"name": "list_issues", "inputSchema": map[string]any{"type": "object"}}},
			}})
			return
		}
		writeMCPTestJSONRPCError(w, req.ID, mcp.JSONRPCMethodNotFound, "Method not found")
	}))
	t.Cleanup(s.Close)
	return s
}

func TestMCPAggregatorRejectsSessionFirstLegacyAggregatedProxy(t *testing.T) {
	ts := startMCPAggregatorCompatTest(t, sessionFirstLegacyMCPUpstream(t).URL)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		aggregated("orders-mcp", "orders"),
		aggregated("github-mcp", "github"),
	))

	assert.Equal(t, http.StatusBadRequest, res.code, res.body)
	assert.Contains(t, res.body, `aggregated MCP proxy \"github-mcp\" does not support MCP version 2026-07-28: upstream requires a legacy session`)
}

// A header-unaware legacy server cannot be told apart from a modern server
// without server/discover, so it is admitted with a warning, not rejected.
func TestMCPAggregatorAdmitsAggregatedProxyWithoutDiscoveryWithAWarning(t *testing.T) {
	ts := startMCPAggregatorCompatTest(t, headerUnawareLegacyMCPUpstream(t).URL)
	hook := log.GetTestHook(t)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github")))

	require.Equal(t, http.StatusOK, res.code, res.body)
	warnings := mcpAggregatorVersionCheckWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0].Data["reason"], "2026-07-28 support not confirmed")
	assert.Contains(t, warnings[0].Data["reason"], "tools/list answered without declaring a version")
}

func TestMCPAggregatorProbeGivesUpOnAHangingUpstreamWithinItsBudget(t *testing.T) {
	release := make(chan struct{})
	hanging := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); hanging.Close() })
	ts := startMCPAggregatorCompatTest(t, hanging.URL)
	ts.Gw.SetConfig(func() config.Config { c := ts.Gw.GetConfig(); c.ProxyDefaultTimeout = 1; return c }())
	assert.Equal(t, time.Second, ts.Gw.mcpAggregatorProbeTimeout())
	hook := log.GetTestHook(t)

	started := time.Now()
	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github")))
	elapsed := time.Since(started)

	require.Equal(t, http.StatusOK, res.code, res.body)
	assert.Less(t, elapsed, 5*time.Second, "the probe is bounded by its budget")
	assert.Len(t, mcpAggregatorVersionCheckWarnings(hook, "github-mcp"), 1)
}

func TestMCPAggregatorProbeTimeoutDefaultsWithoutAProxyTimeout(t *testing.T) {
	gw := newMCPTestGateway(t)
	gw.SetConfig(func() config.Config { c := gw.GetConfig(); c.ProxyDefaultTimeout = 0; return c }())
	assert.Equal(t, mcpAggregatorDefaultProbeTimeout, gw.mcpAggregatorProbeTimeout())
}

func TestMCPAggregatorProbeReachesAggregatedProxiesFromLoopback(t *testing.T) {
	github := newLatestOnlyMCPUpstream(t, "list_issues")
	ts := startMCPAggregatorCompatTest(t, github.URL)
	restricted := githubMCPProxyRuntimeSpec(github.URL)
	restricted.EnableIpWhiteListing = true
	restricted.AllowedIPs = []string{"127.0.0.1"}
	ts.Gw.LoadAPI(restricted)
	hook := log.GetTestHook(t)

	body, err := json.Marshal(mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github")))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.9:4321"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Host = "admin.example.com"
	w := httptest.NewRecorder()
	ts.Gw.validateMCP(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Empty(t, mcpAggregatorVersionCheckWarnings(hook, "github-mcp"), "neither the admin caller's address nor its forwarded client IP reaches the allow-list")
	assert.NotEmpty(t, github.observed())
}
