package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// mcpRoutingUpstream is a 2026-07-28 MCP server whose tools/list descriptors
// are served verbatim. It records the raw body and MCP headers of every
// request, and answers tools/call through an optional handler.
type mcpRoutingUpstream struct {
	*httptest.Server
	mu          sync.Mutex
	descriptors []string
	// listExtra is merged verbatim into the tools/list result.
	listExtra map[string]json.RawMessage
	// rotate serves tools/list in a different order on every call.
	rotate   bool
	listed   int
	requests []mcpRoutingRequest
	// call answers tools/call with a raw JSON-RPC result, or with
	// status and body when it returns a non-zero status.
	call func(r *http.Request, params map[string]json.RawMessage) (result string, status int, body string)
}

type mcpRoutingRequest struct {
	Method     string
	Body       string
	Params     map[string]json.RawMessage
	HeaderName string
	Header     http.Header
}

func newMCPRoutingUpstream(t *testing.T, descriptors ...string) *mcpRoutingUpstream {
	t.Helper()
	u := &mcpRoutingUpstream{descriptors: descriptors}
	u.Server = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.Close)
	return u
}

// namedTools returns minimal descriptors for the given tool names.
func namedTools(names ...string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, `{"name":"`+name+`","description":"`+name+` tool","inputSchema":{"type":"object"}}`)
	}
	return out
}

func (u *mcpRoutingUpstream) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		ID     json.RawMessage            `json:"id"`
		Method string                     `json:"method"`
		Params map[string]json.RawMessage `json:"params"`
	}
	_ = json.Unmarshal(raw, &req)

	u.mu.Lock()
	u.requests = append(u.requests, mcpRoutingRequest{
		Method: req.Method, Body: string(raw), Params: req.Params,
		HeaderName: r.Header.Get(mcp.HeaderName), Header: r.Header.Clone(),
	})
	descriptors := append([]string(nil), u.descriptors...)
	if u.rotate && len(descriptors) > 0 {
		shift := u.listed % len(descriptors)
		descriptors = append(descriptors[shift:], descriptors[:shift]...)
	}
	if req.Method == mcp.MethodToolsList {
		u.listed++
	}
	extra := u.listExtra
	call := u.call
	u.mu.Unlock()

	if version := r.Header.Get(mcp.HeaderProtocolVersion); version != "" && version != mcp.ModernProtocolVersion {
		http.Error(w, "Bad Request: Unsupported protocol version", http.StatusBadRequest)
		return
	}
	var result string
	switch req.Method {
	case mcp.MethodToolsList:
		fields := []string{`"tools":[` + strings.Join(descriptors, ",") + `]`}
		for key, value := range extra {
			fields = append(fields, `"`+key+`":`+string(value))
		}
		result = "{" + strings.Join(fields, ",") + "}"
	case mcp.MethodServerDiscover:
		result = `{"supportedVersions":["2026-07-28"],"capabilities":{"tools":{}}}`
	case mcp.MethodToolsCall:
		if call == nil {
			writeMCPTestJSONRPCError(w, req.ID, mcp.JSONRPCMethodNotFound, "Method not found")
			return
		}
		var status int
		var body string
		result, status, body = call(r, req.Params)
		if status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
			return
		}
	default:
		writeMCPTestJSONRPCError(w, req.ID, mcp.JSONRPCMethodNotFound, "Method not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(req.ID)+`,"result":`+result+`}`)
}

func (u *mcpRoutingUpstream) observed(method string) []mcpRoutingRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []mcpRoutingRequest
	for _, req := range u.requests {
		if req.Method == method {
			out = append(out, req)
		}
	}
	return out
}

// startMCPAggregatorRoutingTest loads company-tools over orders-mcp and
// github-mcp, both remote MCP proxies over the given upstreams.
func startMCPAggregatorRoutingTest(t *testing.T, orders, github *mcpRoutingUpstream) (*Test, string) {
	t.Helper()
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("orders-mcp", orders.URL),
		remoteMCPProxyRuntimeSpec("github-mcp", github.URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	)
	return ts, companyToolsKey(t, ts)
}

func remoteMCPProxyRuntimeSpec(apiID, upstreamURL string) *APISpec {
	return requireToken(mcpRuntimeOASSpec(mcpRuntimeDoc(apiID, upstreamURL), true))
}

// companyToolsKeyWithTools returns a company-tools key whose policy applies
// the given MCP tool rules to the aggregated tool names.
func companyToolsKeyWithTools(t *testing.T, ts *Test, rules user.AccessControlRules) string {
	t.Helper()
	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.AccessRights = map[string]user.AccessDefinition{
			"company-tools": {APIID: "company-tools", APIName: "company-tools", MCPAccessRights: user.MCPAccessRights{Tools: rules}},
		}
	})
	require.NotEmpty(t, key)
	return key
}

// mcpListedTools returns the aggregated tools/list result's tools in the
// order the aggregator served them, with the raw result.
func mcpListedTools(t *testing.T, res mcpTestResponse) ([]string, map[string]json.RawMessage) {
	t.Helper()
	result := mcpTestResultObject(t, res)
	var tools []struct {
		Name string `json:"name"`
	}
	require.NoError(t, json.Unmarshal(result["tools"], &tools), res.body)
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	return names, result
}

func mcpListedDescriptor(t *testing.T, result map[string]json.RawMessage, name string) map[string]json.RawMessage {
	t.Helper()
	var tools []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["tools"], &tools))
	for _, tool := range tools {
		if string(tool["name"]) == `"`+name+`"` {
			return tool
		}
	}
	require.Failf(t, "tool not listed", "%s not in %s", name, result["tools"])
	return nil
}

func TestMCPAggregatorInitializeDeclaresOnlyTools(t *testing.T) {
	ts, key := startMCPAggregatorRoutingTest(t, newMCPRoutingUpstream(t, namedTools("list_orders")...), newMCPRoutingUpstream(t, namedTools("list_issues")...))

	call := modernCall(mcp.MethodInitialize, key)
	call.initializeVersion = mcp.ModernProtocolVersion
	result := mcpTestResultObject(t, postMCPTestCall(t, ts, "/company-tools/", call))

	var capabilities map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["capabilities"], &capabilities))
	assert.Contains(t, capabilities, "tools")
	assert.NotContains(t, capabilities, "resources")
	assert.NotContains(t, capabilities, "prompts")
}

func TestMCPAggregatorListsToolsWithTheirDescriptorsUnchanged(t *testing.T) {
	listIssues := `{"name":"list_issues","title":"List issues","description":"Lists <open> & closed issues","inputSchema":{"type":"object","properties":{"state":{"type":"string","enum":["open","closed"],"default":"open"},"labels":{"type":"array","items":{"type":"string"}}},"required":["state"],"additionalProperties":false},"outputSchema":{"type":"object","properties":{"issues":{"type":"array"}}},"annotations":{"readOnlyHint":true},"_meta":{"com.acme/owner":"dev-tools"},"x-unknown":{"kept":[1,2.50,"3"]}}`
	listOrders := `{"name":"list_orders","description":"List orders","inputSchema":{"type":"object","properties":{"status":{"type":"string"}}}}`
	ts, key := startMCPAggregatorRoutingTest(t, newMCPRoutingUpstream(t, listOrders), newMCPRoutingUpstream(t, listIssues))

	names, result := mcpListedTools(t, postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key)))

	assert.Equal(t, []string{"github__list_issues", "orders__list_orders"}, names)
	for upstreamName, descriptor := range map[string]string{"github__list_issues": listIssues, "orders__list_orders": listOrders} {
		var want map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(descriptor), &want))
		got := mcpListedDescriptor(t, result, upstreamName)
		assert.JSONEq(t, `"`+upstreamName+`"`, string(got["name"]))
		delete(want, "name")
		delete(got, "name")
		require.Len(t, got, len(want))
		for field, raw := range want {
			assert.JSONEq(t, string(raw), string(got[field]), "%s.%s", upstreamName, field)
		}
	}
	assert.Contains(t, string(mcpListedDescriptor(t, result, "github__list_issues")["description"]), "<open> & closed", "descriptions are not HTML-escaped")
}

func TestMCPAggregatorKeepsSameNamedToolsOfDifferentProxiesApart(t *testing.T) {
	ts, key := startMCPAggregatorRoutingTest(t,
		newMCPRoutingUpstream(t, `{"name":"search","description":"Search orders","inputSchema":{"type":"object","properties":{"order_id":{"type":"string"}}}}`),
		newMCPRoutingUpstream(t, `{"name":"search","description":"Search code","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}}`),
	)

	names, result := mcpListedTools(t, postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key)))

	assert.Equal(t, []string{"github__search", "orders__search"}, names)
	assert.JSONEq(t, `"Search code"`, string(mcpListedDescriptor(t, result, "github__search")["description"]))
	assert.JSONEq(t, `"Search orders"`, string(mcpListedDescriptor(t, result, "orders__search")["description"]))
}

func TestMCPAggregatorListsToolsRenamedOnTheAggregatedProxy(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	githubREST := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `[]`) }))
	t.Cleanup(githubREST.Close)

	source := mcpRuntimeDoc("github-rest", githubREST.URL)
	source.Paths.Set("/issues", &openapi3.PathItem{
		Get: &openapi3.Operation{OperationID: "list_issues", Summary: "List issues", Responses: openapi3.NewResponses()},
	})
	proxyDoc := mcpRuntimeDoc("github-mcp", oas.AdapterLoopURL("github-rest"))
	proxyDoc.SetTykMCPServerExtension(&oas.TykMCPServer{Primitives: []oas.TykMCPServerPrimitive{{
		Source:      oas.TykMCPServerSource{OperationID: "list_issues"},
		Name:        "list_open_issues",
		Description: "Lists the open issues of the acme repositories",
	}}})
	ts.Gw.LoadAPI(
		requireToken(mcpRuntimeOASSpec(source, false)),
		requireToken(mcpRuntimeOASSpec(proxyDoc, false)),
		companyToolsRuntimeSpec(aggregated("github-mcp", "github")),
	)

	names, result := mcpListedTools(t, postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, companyToolsKey(t, ts))))

	assert.Equal(t, []string{"github__list_open_issues"}, names)
	assert.JSONEq(t, `"Lists the open issues of the acme repositories"`, string(mcpListedDescriptor(t, result, "github__list_open_issues")["description"]))
}

func TestMCPAggregatorOrdersToolsByAggregatedName(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders", "create_order")...)
	github := newMCPRoutingUpstream(t, namedTools("list_issues", "create_issue")...)
	orders.rotate, github.rotate = true, true
	ts, key := startMCPAggregatorRoutingTest(t, orders, github)

	for i := 0; i < 3; i++ {
		names, _ := mcpListedTools(t, postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key)))
		assert.Equal(t, []string{"github__create_issue", "github__list_issues", "orders__create_order", "orders__list_orders"}, names, "call %d", i+1)
	}
	assert.Len(t, github.observed(mcp.MethodToolsList), 3, "the upstream answered in a different order every time")
}

func TestMCPAggregatorFiltersToolsPerConsumerKeepingTheOrder(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders", "create_order")...)
	github := newMCPRoutingUpstream(t, namedTools("list_issues", "create_issue")...)
	orders.rotate, github.rotate = true, true
	ts, _ := startMCPAggregatorRoutingTest(t, orders, github)
	key := companyToolsKeyWithTools(t, ts, user.AccessControlRules{Blocked: []string{"github__create_issue"}})

	for i := 0; i < 3; i++ {
		names, result := mcpListedTools(t, postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key)))
		assert.Equal(t, []string{"github__list_issues", "orders__create_order", "orders__list_orders"}, names, "call %d", i+1)
		assert.JSONEq(t, `"private"`, string(result["cacheScope"]))
	}

	allowed := companyToolsKeyWithTools(t, ts, user.AccessControlRules{Allowed: []string{"orders__.*"}})
	names, _ := mcpListedTools(t, postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, allowed)))
	assert.Equal(t, []string{"orders__create_order", "orders__list_orders"}, names)
}

func TestMCPAggregatorListIsPrivateAndImmediatelyStale(t *testing.T) {
	for name, hints := range map[string]struct{ orders, github map[string]json.RawMessage }{
		"github public for a minute":                  {github: map[string]json.RawMessage{"cacheScope": json.RawMessage(`"public"`), "ttlMs": json.RawMessage(`60000`)}},
		"orders public for five minutes, github none": {orders: map[string]json.RawMessage{"cacheScope": json.RawMessage(`"public"`), "ttlMs": json.RawMessage(`300000`)}},
		"no hints anywhere":                           {},
	} {
		t.Run(name, func(t *testing.T) {
			orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
			github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
			orders.listExtra, github.listExtra = hints.orders, hints.github
			ts, key := startMCPAggregatorRoutingTest(t, orders, github)

			names, result := mcpListedTools(t, postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key)))

			assert.Equal(t, []string{"github__list_issues", "orders__list_orders"}, names)
			assert.JSONEq(t, `"private"`, string(result["cacheScope"]))
			assert.JSONEq(t, `0`, string(result["ttlMs"]))
		})
	}
}

func TestMCPAggregatorListIsNotSharedBetweenConsumersWithResponseCaching(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	aggregator := companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github"))
	aggregator.CacheOptions = apidef.CacheOptions{EnableCache: true, CacheTimeout: 60, CacheAllSafeRequests: true}
	for name, version := range aggregator.VersionData.Versions {
		aggregator.VersionData.Versions[name] = withCachedPost(version)
	}
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("orders-mcp", newMCPRoutingUpstream(t, namedTools("list_orders")...).URL),
		remoteMCPProxyRuntimeSpec("github-mcp", newMCPRoutingUpstream(t, namedTools("list_issues")...).URL),
		aggregator,
	)
	acme := companyToolsKeyWithTools(t, ts, user.AccessControlRules{})
	globex := companyToolsKeyWithTools(t, ts, user.AccessControlRules{Blocked: []string{"github__.*"}})

	first := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, acme))
	names, _ := mcpListedTools(t, first)
	assert.Equal(t, []string{"github__list_issues", "orders__list_orders"}, names)

	second := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, globex))
	names, _ = mcpListedTools(t, second)
	assert.Equal(t, []string{"orders__list_orders"}, names)
	assert.Empty(t, second.header.Get(cachedResponseHeader))

	again := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, acme))
	assert.Empty(t, again.header.Get(cachedResponseHeader), "aggregator responses are never served from the response cache")
}

// withCachedPost caches POST / on the version, the endpoint an MCP client posts to.
func withCachedPost(version apidef.VersionInfo) apidef.VersionInfo {
	version.UseExtendedPaths = true
	version.ExtendedPaths.AdvanceCacheConfig = append(version.ExtendedPaths.AdvanceCacheConfig, apidef.CacheMeta{
		Method: http.MethodPost, Path: "/", CacheOnlyResponseCodes: []int{http.StatusOK},
	})
	return version
}

func TestMCPAggregatorOmitsAggregatedProxyWhoseUpstreamIsDown(t *testing.T) {
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	ts, key := startMCPAggregatorRoutingTest(t, newMCPRoutingUpstream(t, namedTools("list_orders", "create_order")...), github)
	github.Close()
	hook := log.GetTestHook(t)

	names, _ := mcpListedTools(t, postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key)))

	assert.Equal(t, []string{"orders__create_order", "orders__list_orders"}, names)
	warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, "github", warnings[0].Data["alias"])
}

func TestMCPAggregatorAnswersPing(t *testing.T) {
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	ts, key := startMCPAggregatorRoutingTest(t, newMCPRoutingUpstream(t, namedTools("list_orders")...), github)

	res := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodPing, key))

	assert.JSONEq(t, `{}`, string(mcpTestResultObjectRaw(t, res)))
	assert.Contains(t, res.body, `"id":9`)
	assert.Empty(t, github.observed(mcp.MethodPing), "ping is answered by the aggregator itself")

	unauthenticated := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodPing, ""))
	assert.Equal(t, http.StatusUnauthorized, unauthenticated.status, unauthenticated.body)

	_, proxyKey := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.AccessRights = map[string]user.AccessDefinition{"github-mcp": {APIID: "github-mcp", APIName: "github-mcp"}}
	})
	direct := postMCPTestCall(t, ts, "/github-mcp/", modernCall(mcp.MethodPing, proxyKey))
	assert.Equal(t, http.StatusNotFound, direct.status, direct.body)
	require.NotNil(t, direct.rpc.Error, direct.body)
	assert.Equal(t, mcp.JSONRPCMethodNotFound, direct.rpc.Error.Code, "other MCP proxies keep treating ping as removed on 2026-07-28")
}

func mcpTestResultObjectRaw(t *testing.T, res mcpTestResponse) json.RawMessage {
	t.Helper()
	require.Equal(t, http.StatusOK, res.status, res.body)
	require.Nil(t, res.rpc.Error, res.body)
	return res.rpc.Result
}

func TestMCPAggregatorSkipsTheResponseCacheLookup(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	spec := companyToolsRuntimeSpec(aggregated("github-mcp", "github"))
	spec.CacheOptions = apidef.CacheOptions{EnableCache: true, CacheTimeout: 60, CacheAllSafeRequests: true}
	store := &storage.RedisCluster{KeyPrefix: "cache-", IsCache: true, ConnectionHandler: ts.Gw.StorageConnectionHandler}
	mw := &RedisCacheMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: ts.Gw}, store: store}
	mw.Init()
	req := httptest.NewRequest(http.MethodGet, "/company-tools/", nil)
	ctxSetCacheOptions(req, &cacheOptions{key: "armed-by-an-earlier-api"})

	_, code := mw.ProcessRequest(httptest.NewRecorder(), req, nil)

	assert.Equal(t, http.StatusOK, code)
	assert.Nil(t, ctxGetCacheOptions(req), "no cache key is armed for an aggregator response")
}
