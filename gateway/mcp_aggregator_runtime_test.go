package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/user"
)

const mcpAggregatorRuntimeOrg = "acme"

// mockRemoteMCPServer answers tools/list with the current tool names and
// records the protocol headers of the last request it served.
type mockRemoteMCPServer struct {
	*httptest.Server
	mu           sync.Mutex
	tools        []string
	sse          bool
	failStatus   atomic.Int32
	lastProtocol string
	lastMethod   string
	lastAuth     string
	// pager, when set, serves tools/list pages by cursor.
	pager func(cursor string) (tools []string, next string)
	// descriptionPadding lengthens every tool description by this many bytes.
	descriptionPadding int
}

func newMockRemoteMCPServer(t *testing.T, tools ...string) *mockRemoteMCPServer {
	t.Helper()
	m := &mockRemoteMCPServer{tools: tools}
	m.Server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.Close)
	return m
}

func (m *mockRemoteMCPServer) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     any    `json:"id"`
		Method string `json:"method"`
		Params struct {
			Cursor string `json:"cursor"`
		} `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	m.mu.Lock()
	m.lastProtocol = r.Header.Get(mcp.HeaderProtocolVersion)
	m.lastMethod = r.Header.Get(mcp.HeaderMethod)
	m.lastAuth = r.Header.Get("Authorization")
	tools := append([]string(nil), m.tools...)
	sse := m.sse
	pager := m.pager
	padding := strings.Repeat("x", m.descriptionPadding)
	m.mu.Unlock()
	next := ""
	if pager != nil {
		tools, next = pager(req.Params.Cursor)
	}

	if status := m.failStatus.Load(); status != 0 {
		w.WriteHeader(int(status))
		return
	}
	if req.Method != mcp.MethodToolsList {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": mcp.JSONRPCMethodNotFound, "message": "not found"}})
		return
	}

	list := make([]map[string]any, 0, len(tools))
	for _, name := range tools {
		list = append(list, map[string]any{"name": name, "description": name + " tool" + padding, "inputSchema": map[string]any{"type": "object"}})
	}
	result := map[string]any{"tools": list}
	if next != "" {
		result["nextCursor"] = next
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	if sse {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (m *mockRemoteMCPServer) observed() (protocol, method, auth string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastProtocol, m.lastMethod, m.lastAuth
}

func mcpRuntimeOASSpec(doc *oas.OAS, markMCP bool) *APISpec {
	api := &apidef.APIDefinition{}
	doc.ExtractTo(api)
	api.IsOAS = true
	if markMCP {
		api.MarkAsMCP()
	}
	return &APISpec{APIDefinition: api, OAS: *doc}
}

func mcpRuntimeDoc(apiID, upstreamURL string) *oas.OAS {
	doc := &oas.OAS{T: openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: apiID, Version: "1.0.0"},
		Paths:   openapi3.NewPaths(),
	}}
	doc.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			ID:    apiID,
			OrgID: mcpAggregatorRuntimeOrg,
			Name:  apiID,
			State: oas.State{Active: true},
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: "/" + apiID + "/", Strip: true},
		},
		Upstream: oas.Upstream{URL: upstreamURL},
	})
	return doc
}

func requireToken(spec *APISpec) *APISpec {
	spec.UseKeylessAccess = false
	spec.UseStandardAuth = true
	spec.AuthConfigs = map[string]apidef.AuthConfig{apidef.AuthTokenType: {AuthHeaderName: "Authorization"}}
	return spec
}

func ordersRESTSourceSpec(upstreamURL string, withCancel bool) *APISpec {
	doc := mcpRuntimeDoc("orders-rest", upstreamURL)
	doc.Paths.Set("/orders", &openapi3.PathItem{
		Get:  &openapi3.Operation{OperationID: "list_orders", Summary: "List orders", Responses: openapi3.NewResponses()},
		Post: &openapi3.Operation{OperationID: "create_order", Summary: "Create order", Responses: openapi3.NewResponses()},
	})
	if withCancel {
		doc.Paths.Set("/orders/{id}/cancel", &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "cancel_order",
				Summary:     "Cancel order",
				Parameters: openapi3.Parameters{{Value: &openapi3.Parameter{
					Name: "id", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()},
				}}},
				Responses: openapi3.NewResponses(),
			},
		})
	}
	return requireToken(mcpRuntimeOASSpec(doc, false))
}

func ordersMCPProxyRuntimeSpec() *APISpec {
	return requireToken(mcpRuntimeOASSpec(mcpRuntimeDoc("orders-mcp", oas.AdapterLoopURL("orders-rest")), false))
}

func githubMCPProxyRuntimeSpec(upstreamURL string) *APISpec {
	return requireToken(mcpRuntimeOASSpec(mcpRuntimeDoc("github-mcp", upstreamURL), true))
}

func companyToolsRuntimeSpec(upstreams ...oas.TykMCPAggregatorUpstream) *APISpec {
	doc := mcpRuntimeDoc("company-tools", oas.MCPAggregatorTargetURL)
	doc.SetTykMCPAggregatorExtension(&oas.TykMCPAggregator{Upstreams: upstreams})
	return requireToken(mcpRuntimeOASSpec(doc, true))
}

func companyToolsKey(t *testing.T, ts *Test) string {
	t.Helper()
	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.AccessRights = map[string]user.AccessDefinition{
			"company-tools": {APIID: "company-tools", APIName: "company-tools"},
		}
	})
	require.NotEmpty(t, key)
	return key
}

type mcpToolsListResult struct {
	status int
	body   string
	tools  []string
}

func postModernToolsList(t *testing.T, ts *Test, listenPath, key string) mcpToolsListResult {
	t.Helper()
	return postModernToolsListWithHeader(t, ts, listenPath, key, nil)
}

// postModernToolsListWithHeader posts tools/list with extra request headers.
func postModernToolsListWithHeader(t *testing.T, ts *Test, listenPath, key string, header http.Header) mcpToolsListResult {
	t.Helper()

	body := `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+listenPath, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(mcp.HeaderProtocolVersion, mcp.ModernProtocolVersion)
	req.Header.Set(mcp.HeaderMethod, mcp.MethodToolsList)
	if key != "" {
		req.Header.Set("Authorization", key)
	}
	for name, values := range header {
		req.Header[name] = values
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	result := mcpToolsListResult{status: resp.StatusCode, body: string(raw)}
	var parsed struct {
		ID     any `json:"id"`
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &parsed) == nil {
		for _, tool := range parsed.Result.Tools {
			result.tools = append(result.tools, tool.Name)
		}
		sort.Strings(result.tools)
	}
	return result
}

func startMCPAggregatorRuntimeTest(t *testing.T) (*Test, *mockRemoteMCPServer, *httptest.Server) {
	t.Helper()
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	github := newMockRemoteMCPServer(t, "search_repos", "create_issue")
	ordersBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(ordersBackend.Close)
	return ts, github, ordersBackend
}

func TestMCPAggregatorEndpointServesToolsFromMixedAggregatedProxyTypes(t *testing.T) {
	ts, github, ordersBackend := startMCPAggregatorRuntimeTest(t)

	ts.Gw.LoadAPI(
		ordersRESTSourceSpec(ordersBackend.URL, false),
		ordersMCPProxyRuntimeSpec(),
		githubMCPProxyRuntimeSpec(github.URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	)
	key := companyToolsKey(t, ts)

	res := postModernToolsList(t, ts, "/company-tools/", key)

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Equal(t, []string{
		"github__create_issue",
		"github__search_repos",
		"orders__create_order",
		"orders__list_orders",
	}, res.tools)
	assert.Contains(t, res.body, `"id":7`)

	protocol, method, auth := github.observed()
	assert.Equal(t, mcp.ModernProtocolVersion, protocol, "fan-out uses the modern protocol")
	assert.Equal(t, mcp.MethodToolsList, method)
	assert.Empty(t, auth, "the caller's credential is not forwarded to aggregated proxies")
}

func TestMCPAggregatorRunsItsOwnAuthenticationBeforeServing(t *testing.T) {
	ts, github, _ := startMCPAggregatorRuntimeTest(t)

	ts.Gw.LoadAPI(
		githubMCPProxyRuntimeSpec(github.URL),
		companyToolsRuntimeSpec(aggregated("github-mcp", "github")),
	)
	key := companyToolsKey(t, ts)

	unauthenticated := postModernToolsList(t, ts, "/company-tools/", "")
	assert.Equal(t, http.StatusUnauthorized, unauthenticated.status, unauthenticated.body)

	direct := postModernToolsList(t, ts, "/github-mcp/", key)
	assert.Equal(t, http.StatusForbidden, direct.status, "the aggregator key has no access to the aggregated proxy itself")

	aggregatedRes := postModernToolsList(t, ts, "/company-tools/", key)
	assert.Equal(t, http.StatusOK, aggregatedRes.status, aggregatedRes.body)
	assert.Equal(t, []string{"github__create_issue", "github__search_repos"}, aggregatedRes.tools)
}

func TestMCPAggregatorParsesEventStreamToolsListResponses(t *testing.T) {
	ts, github, _ := startMCPAggregatorRuntimeTest(t)
	github.sse = true

	ts.Gw.LoadAPI(
		githubMCPProxyRuntimeSpec(github.URL),
		companyToolsRuntimeSpec(aggregated("github-mcp", "github")),
	)

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Equal(t, []string{"github__create_issue", "github__search_repos"}, res.tools)
}

func mcpAggregatorOmissionWarnings(hook interface{ AllEntries() []*logrus.Entry }, upstreamAPIID string) []*logrus.Entry {
	var out []*logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && entry.Message == mcpAggregatorUpstreamOmittedMsg && entry.Data["upstream_api_id"] == upstreamAPIID {
			out = append(out, entry)
		}
	}
	return out
}

func TestMCPAggregatorOmitsUndeployedAggregatedProxyAndServesTheRest(t *testing.T) {
	ts, github, ordersBackend := startMCPAggregatorRuntimeTest(t)
	aggregator := companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github"))

	ts.Gw.LoadAPI(
		ordersRESTSourceSpec(ordersBackend.URL, false),
		ordersMCPProxyRuntimeSpec(),
		githubMCPProxyRuntimeSpec(github.URL),
		aggregator,
	)
	key := companyToolsKey(t, ts)
	before := postModernToolsList(t, ts, "/company-tools/", key)
	require.Contains(t, before.tools, "orders__list_orders")

	hook := log.GetTestHook(t)
	ts.Gw.LoadAPI(
		githubMCPProxyRuntimeSpec(github.URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	)

	res := postModernToolsList(t, ts, "/company-tools/", key)

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Equal(t, []string{"github__create_issue", "github__search_repos"}, res.tools)
	warnings := mcpAggregatorOmissionWarnings(hook, "orders-mcp")
	require.NotEmpty(t, warnings)
	for _, warning := range warnings {
		assert.Equal(t, "company-tools", warning.Data["aggregator_api_id"])
		assert.Equal(t, "orders", warning.Data["alias"])
		assert.Equal(t, "not loaded on this gateway", warning.Data["reason"])
	}
}

func TestMCPAggregatorOmitsFailingAggregatedProxyAndServesTheRest(t *testing.T) {
	ts, github, ordersBackend := startMCPAggregatorRuntimeTest(t)
	github.failStatus.Store(http.StatusBadGateway)

	ts.Gw.LoadAPI(
		ordersRESTSourceSpec(ordersBackend.URL, false),
		ordersMCPProxyRuntimeSpec(),
		githubMCPProxyRuntimeSpec(github.URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	)
	hook := log.GetTestHook(t)

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Equal(t, []string{"orders__create_order", "orders__list_orders"}, res.tools)
	warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, "github", warnings[0].Data["alias"])
	assert.Contains(t, warnings[0].Data["reason"], "tools/list failed")
}

func TestMCPAggregatorCatalogueFollowsSourceChangesAfterReload(t *testing.T) {
	ts, github, ordersBackend := startMCPAggregatorRuntimeTest(t)
	load := func(withCancel bool) {
		ts.Gw.LoadAPI(
			ordersRESTSourceSpec(ordersBackend.URL, withCancel),
			ordersMCPProxyRuntimeSpec(),
			githubMCPProxyRuntimeSpec(github.URL),
			companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
		)
	}

	load(false)
	key := companyToolsKey(t, ts)
	before := postModernToolsList(t, ts, "/company-tools/", key)
	require.Equal(t, http.StatusOK, before.status, before.body)
	assert.NotContains(t, before.tools, "orders__cancel_order")

	load(true)
	after := postModernToolsList(t, ts, "/company-tools/", key)

	require.Equal(t, http.StatusOK, after.status, after.body)
	assert.Contains(t, after.tools, "orders__cancel_order")
	assert.Contains(t, after.tools, "github__search_repos")
}

func TestMCPAggregatorRejectsUnsupportedMethods(t *testing.T) {
	ts, github, _ := startMCPAggregatorRuntimeTest(t)
	ts.Gw.LoadAPI(
		githubMCPProxyRuntimeSpec(github.URL),
		companyToolsRuntimeSpec(aggregated("github-mcp", "github")),
	)
	key := companyToolsKey(t, ts)

	body := `{"jsonrpc":"2.0","id":3,"method":"prompts/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/company-tools/", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(mcp.HeaderProtocolVersion, mcp.ModernProtocolVersion)
	req.Header.Set(mcp.HeaderMethod, "prompts/list")
	req.Header.Set("Authorization", key)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusNotFound, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), `"code":-32601`)
	assert.Contains(t, string(raw), `"id":3`)
}

func TestMCPAggregatorLoopTrustRejectsUpstreamNotAdmitted(t *testing.T) {
	gw := newMCPTestGateway(t)
	github := mcpManagedTestSpec("github-mcp")
	github.OrgID = mcpAggregatorRuntimeOrg
	payments := mcpManagedTestSpec("payments-mcp")
	payments.OrgID = mcpAggregatorRuntimeOrg
	gw.mcpAggregatorIndex.Set(computeMCPAggregation([]*APISpec{
		github, payments, mcpAggregatorSpec("company-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github")),
	}))

	process := func(spec *APISpec, trust *mcpAggregatorLoopTrust) (int, *http.Request) {
		mw := &MCPAggregatorLoopAuthBypassMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctxSetMCPAggregatorLoopTrust(req, trust)
		_, code := mw.ProcessRequest(httptest.NewRecorder(), req, nil)
		return code, req
	}

	code, req := process(github, &mcpAggregatorLoopTrust{OrgID: mcpAggregatorRuntimeOrg, AggregatorAPIID: "company-tools", UpstreamAPIID: "github-mcp"})
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, StatusOkAndIgnore, ctxGetRequestStatus(req))
	assert.False(t, isMCPAggregatorLoopRequest(req), "trust is consumed by the hop it was issued for")

	code, _ = process(payments, &mcpAggregatorLoopTrust{OrgID: mcpAggregatorRuntimeOrg, AggregatorAPIID: "company-tools", UpstreamAPIID: "payments-mcp"})
	assert.Equal(t, http.StatusForbidden, code, "an upstream the aggregator does not reference is not trusted")

	code, _ = process(payments, &mcpAggregatorLoopTrust{OrgID: mcpAggregatorRuntimeOrg, AggregatorAPIID: "company-tools", UpstreamAPIID: "github-mcp"})
	assert.Equal(t, http.StatusForbidden, code, "trust issued for another upstream is not accepted")
}

func TestMCPAggregatorLoopTrustDoesNotAuthenticateFurtherLoops(t *testing.T) {
	ts, github, _ := startMCPAggregatorRuntimeTest(t)

	// github-mcp loops to secret-rest, which requires its own credential.
	secret := requireToken(mcpRuntimeOASSpec(mcpRuntimeDoc("secret-rest", github.URL), false))
	ts.Gw.LoadAPI(
		secret,
		githubMCPProxyRuntimeSpec("tyk://secret-rest/"),
		companyToolsRuntimeSpec(aggregated("github-mcp", "github")),
	)
	hook := log.GetTestHook(t)

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Empty(t, res.tools, "the aggregator's per-hop trust must not reach secret-rest")
	warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0].Data["reason"], "HTTP 401")

	_, both := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.AccessRights = map[string]user.AccessDefinition{
			"github-mcp":  {APIID: "github-mcp", APIName: "github-mcp"},
			"secret-rest": {APIID: "secret-rest", APIName: "secret-rest"},
		}
	})
	direct := postModernToolsList(t, ts, "/github-mcp/", both)
	assert.Equal(t, http.StatusOK, direct.status, "the loop itself still works for a caller entitled to both APIs: %s", direct.body)
}

func TestMCPAggregatorLoopSessionIsScopedToTheAdmittedProxy(t *testing.T) {
	gw := newMCPTestGateway(t)
	github := mcpManagedTestSpec("github-mcp")
	github.OrgID = mcpAggregatorRuntimeOrg
	gw.mcpAggregatorIndex.Set(computeMCPAggregation([]*APISpec{
		github, mcpAggregatorSpec("company-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github")),
	}))
	mw := &MCPAggregatorLoopAuthBypassMiddleware{BaseMiddleware: &BaseMiddleware{Spec: github, Gw: gw}}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctxSetMCPAggregatorLoopTrust(req, &mcpAggregatorLoopTrust{OrgID: mcpAggregatorRuntimeOrg, AggregatorAPIID: "company-tools", UpstreamAPIID: "github-mcp"})

	_, code := mw.ProcessRequest(httptest.NewRecorder(), req, nil)

	require.Equal(t, http.StatusOK, code)
	session := ctxGetSession(req)
	require.NotNil(t, session)
	assert.Equal(t, []string{"github-mcp"}, mapKeys(session.AccessRights))

	httpctx.SetSelfLooping(req, true)
	endMCPAggregatorLoopSession(req)
	assert.Nil(t, ctxGetSession(req))
	assert.False(t, httpctx.IsSelfLooping(req))

	userReq := httptest.NewRequest(http.MethodPost, "/", nil)
	setSessionForTest(userReq, &user.SessionState{KeyID: "user-key"})
	endMCPAggregatorLoopSession(userReq)
	assert.NotNil(t, ctxGetSession(userReq), "ordinary sessions are left alone")
}

func mapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func TestMCPAggregatorFollowsToolsListCursors(t *testing.T) {
	ts, github, _ := startMCPAggregatorRuntimeTest(t)
	github.pager = func(cursor string) ([]string, string) {
		if cursor == "" {
			return []string{"search_repos"}, "page-2"
		}
		return []string{"create_issue"}, ""
	}
	ts.Gw.LoadAPI(githubMCPProxyRuntimeSpec(github.URL), companyToolsRuntimeSpec(aggregated("github-mcp", "github")))

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Equal(t, []string{"github__create_issue", "github__search_repos"}, res.tools)
}

func TestMCPAggregatorOmitsAggregatedProxyRepeatingACursor(t *testing.T) {
	ts, github, _ := startMCPAggregatorRuntimeTest(t)
	github.pager = func(string) ([]string, string) { return []string{"search_repos"}, "same" }
	ts.Gw.LoadAPI(githubMCPProxyRuntimeSpec(github.URL), companyToolsRuntimeSpec(aggregated("github-mcp", "github")))
	hook := log.GetTestHook(t)

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Empty(t, res.tools)
	warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, `tools/list failed: repeated cursor "same"`, warnings[0].Data["reason"])
}

func TestMCPAggregatorOmitsAggregatedProxyExceedingThePageLimit(t *testing.T) {
	ts, github, _ := startMCPAggregatorRuntimeTest(t)
	var pages atomic.Int32
	github.pager = func(string) ([]string, string) {
		n := pages.Add(1)
		return []string{fmt.Sprintf("tool_%d", n)}, fmt.Sprintf("page-%d", n+1)
	}
	ts.Gw.LoadAPI(githubMCPProxyRuntimeSpec(github.URL), companyToolsRuntimeSpec(aggregated("github-mcp", "github")))
	hook := log.GetTestHook(t)

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Empty(t, res.tools, "a partial list is not served")
	assert.EqualValues(t, mcpAggregatorMaxListPages, pages.Load())
	warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, "tools/list failed: returned more than 100 pages", warnings[0].Data["reason"])
}

func TestMCPAggregatorOmitsAggregatedProxyWithOversizedResponse(t *testing.T) {
	ts, github, ordersBackend := startMCPAggregatorRuntimeTest(t)
	ts.Gw.LoadAPI(
		ordersRESTSourceSpec(ordersBackend.URL, false),
		ordersMCPProxyRuntimeSpec(),
		githubMCPProxyRuntimeSpec(github.URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	)
	cfg := ts.Gw.GetConfig()
	cfg.HttpServerOptions.MaxResponseBodySize = 1200
	ts.Gw.SetConfig(cfg)
	github.mu.Lock()
	for i := 0; i < 50; i++ {
		github.tools = append(github.tools, fmt.Sprintf("generated_tool_%02d", i))
	}
	github.mu.Unlock()
	hook := log.GetTestHook(t)

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Equal(t, []string{"orders__create_order", "orders__list_orders"}, res.tools)
	warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, "tools/list failed: response exceeds 1200 bytes", warnings[0].Data["reason"])
}

func TestMCPAggregatorWarnsAboutAggregatedToolsWithoutName(t *testing.T) {
	ts, github, _ := startMCPAggregatorRuntimeTest(t)
	github.tools = []string{"search_repos", ""}
	ts.Gw.LoadAPI(githubMCPProxyRuntimeSpec(github.URL), companyToolsRuntimeSpec(aggregated("github-mcp", "github")))
	hook := log.GetTestHook(t)

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Equal(t, []string{"github__search_repos"}, res.tools)
	var found bool
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && entry.Message == mcpAggregatorUnnamedToolMsg {
			found = true
			assert.Equal(t, "github-mcp", entry.Data["upstream_api_id"])
			assert.Equal(t, "github", entry.Data["alias"])
		}
	}
	assert.True(t, found)
}

func TestMCPAggregatorUpstreamContextKeepsOnlyCancellationTraceSpanAndClientIP(t *testing.T) {
	type otherKey struct{}
	spanContext := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    oteltrace.TraceID{1},
		SpanID:     oteltrace.SpanID{2},
		TraceFlags: oteltrace.FlagsSampled,
	})
	parent, cancel := context.WithCancel(context.WithValue(oteltrace.ContextWithSpanContext(context.Background(), spanContext), otherKey{}, "leak"))

	upstream := mcpAggregatorUpstreamRequestContext(parent, "203.0.113.7")

	assert.Equal(t, spanContext, oteltrace.SpanContextFromContext(upstream))
	assert.Nil(t, upstream.Value(otherKey{}))
	assert.Equal(t, "203.0.113.7", request.RealIP((&http.Request{RemoteAddr: "10.0.0.1:1234"}).WithContext(upstream)))
	cancel()
	assert.ErrorIs(t, upstream.Err(), context.Canceled)
}
