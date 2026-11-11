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
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// mcpRoutingUpstream is a 2026-07-28 MCP server whose tools/list descriptors
// are served verbatim. It records the raw body and MCP headers of every
// request, and answers tools/call through an optional handler.
type mcpRoutingUpstream struct {
	*httptest.Server
	t           *testing.T
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
	u := &mcpRoutingUpstream{t: t, descriptors: descriptors}
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
		if !mcpRoutingUpstreamHasTool(descriptors, req.Params["name"]) {
			// The go-sdk's answer to a tool it does not have.
			writeMCPTestJSONRPCError(u.t, w, req.ID, mcp.JSONRPCInvalidParams, "unknown tool "+string(req.Params["name"]))
			return
		}
		if call == nil {
			writeMCPTestJSONRPCError(u.t, w, req.ID, mcp.JSONRPCMethodNotFound, "Method not found")
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
		writeMCPTestJSONRPCError(u.t, w, req.ID, mcp.JSONRPCMethodNotFound, "Method not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(req.ID)+`,"result":`+result+`}`)
}

func mcpRoutingUpstreamHasTool(descriptors []string, name json.RawMessage) bool {
	for _, descriptor := range descriptors {
		var tool struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(descriptor), &tool) == nil && `"`+tool.Name+`"` == string(name) {
			return true
		}
	}
	return false
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

// postMCPToolsCall sends a 2026-07-28 tools/call with raw params, mirroring the
// tool name in Mcp-Name, and any extra headers.
func postMCPToolsCall(t *testing.T, ts *Test, key, params string, extra ...string) mcpTestResponse {
	t.Helper()
	return postMCPToolsCallTo(t, ts, "/company-tools/", key, params, extra...)
}

func postMCPToolsCallTo(t *testing.T, ts *Test, listenPath, key, params string, extra ...string) mcpTestResponse {
	t.Helper()
	var decoded struct {
		Name string `json:"name"`
	}
	require.NoError(t, json.Unmarshal([]byte(params), &decoded))
	body := `{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":` + params + `}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+listenPath, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(mcp.HeaderProtocolVersion, mcp.ModernProtocolVersion)
	req.Header.Set(mcp.HeaderMethod, mcp.MethodToolsCall)
	req.Header.Set(mcp.HeaderName, decoded.Name)
	req.Header.Set("Authorization", key)
	for i := 0; i+1 < len(extra); i += 2 {
		req.Header.Set(extra[i], extra[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	out := mcpTestResponse{status: resp.StatusCode, body: string(raw), header: resp.Header}
	_ = json.Unmarshal(raw, &out.rpc)
	return out
}

// toolCallParams builds tools/call params whose arguments and extra _meta
// entries are kept byte for byte.
func toolCallParams(name, arguments, extraMeta string) string {
	meta := `"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}`
	if extraMeta != "" {
		meta += "," + extraMeta
	}
	params := `{"name":"` + name + `"`
	if arguments != "" {
		params += `,"arguments":` + arguments
	}
	return params + `,"_meta":{` + meta + `}}`
}

func answering(result string) func(*http.Request, map[string]json.RawMessage) (string, int, string) {
	return func(*http.Request, map[string]json.RawMessage) (string, int, string) { return result, 0, "" }
}

func TestMCPAggregatorRoutesToolCallToTheOwningProxy(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders", "create_order")...)
	github := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = answering(`{"content":[{"type":"text","text":"2 open orders"}]}`)
	ts, key := startMCPAggregatorRoutingTest(t, orders, github)

	res := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{"status": "open"}`, ""))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":"call-1","result":{"content":[{"type":"text","text":"2 open orders"}]}}`, res.body)
	calls := orders.observed(mcp.MethodToolsCall)
	require.Len(t, calls, 1)
	assert.JSONEq(t, `"list_orders"`, string(calls[0].Params["name"]))
	assert.Equal(t, "list_orders", calls[0].HeaderName, "Mcp-Name mirrors the forwarded name")
	assert.Equal(t, mcp.MethodToolsCall, calls[0].Header.Get(mcp.HeaderMethod))
	assert.Equal(t, `{"status": "open"}`, string(calls[0].Params["arguments"]))
	assert.Empty(t, github.observed(mcp.MethodToolsCall), "only the owning proxy is called")
}

func TestMCPAggregatorSplitsTheAliasAtTheFirstSeparator(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("get__order", "get")...)
	orders.call = answering(`{"content":[{"type":"text","text":"order o-1"}]}`)
	ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))

	res := postMCPToolsCall(t, ts, key, toolCallParams("orders__get__order", `{"id":"o-1"}`, ""))

	require.Equal(t, http.StatusOK, res.status, res.body)
	calls := orders.observed(mcp.MethodToolsCall)
	require.Len(t, calls, 1)
	assert.JSONEq(t, `"get__order"`, string(calls[0].Params["name"]))
	assert.Equal(t, "get__order", calls[0].HeaderName)
}

func TestMCPAggregatorRejectsUnknownTools(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = answering(`{"content":[]}`)
	ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))

	for _, name := range []string{"billing__list_invoices", "orders__cancel_order", "list_orders", "__list_orders", "orders__", "orders_list_orders", "ORDERS__list_orders"} {
		t.Run(name, func(t *testing.T) {
			res := postMCPToolsCall(t, ts, key, toolCallParams(name, `{}`, ""))

			assert.Equal(t, http.StatusBadRequest, res.status, res.body)
			require.NotNil(t, res.rpc.Error, res.body)
			assert.Equal(t, mcp.JSONRPCInvalidParams, res.rpc.Error.Code)
			assert.Equal(t, `unknown tool "`+name+`"`, res.rpc.Error.Message)
			assert.Contains(t, res.body, `"id":"call-1"`)
		})
	}
	calls := orders.observed(mcp.MethodToolsCall)
	require.Len(t, calls, 1, "only a configured alias is forwarded; the proxy rejects a tool it does not have")
	assert.JSONEq(t, `"cancel_order"`, string(calls[0].Params["name"]))
	assert.Empty(t, orders.observed(mcp.MethodToolsList), "names are resolved without listing the proxy")
}

func TestMCPAggregatorReportsUnknownToolsOfAnAPIToMCPProxy(t *testing.T) {
	ts, key := startMCPAggregatorProtocolTest(t, newDualMCPUpstream(t, "list_issues"))

	res := postMCPToolsCall(t, ts, key, toolCallParams("orders__cancel_order", `{}`, ""))

	assert.Equal(t, http.StatusBadRequest, res.status, res.body)
	require.NotNil(t, res.rpc.Error, res.body)
	assert.Equal(t, mcp.JSONRPCInvalidParams, res.rpc.Error.Code)
	assert.Equal(t, `unknown tool "orders__cancel_order"`, res.rpc.Error.Message, "the adapter's own unknown-tool error names the aggregated tool")
}

func TestMCPAggregatorSendsEachToolCallToTheProxyExactlyOnce(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = answering(`{"content":[]}`)
	ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))

	const calls = 5
	for i := 0; i < calls; i++ {
		res := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""))
		require.Equal(t, http.StatusOK, res.status, res.body)
	}

	assert.Len(t, orders.observed(mcp.MethodToolsCall), calls)
	assert.Empty(t, orders.observed(mcp.MethodToolsList))
}

// TestMCPAggregatorToolCallsCountOnceAgainstTheProxysRateLimit checks that
// an aggregated call spends the proxy's API-level rate limit exactly as a
// direct call to the proxy does: the aggregator adds no request of its own.
// Both are refused at the same call. That call is not the 11th of a 10 per
// minute limit, because the proxy's JSON-RPC routing checks the API-level
// limit again on each VEM hop of a tools/call (listen path, tools/call VEM,
// tool VEM), on direct calls as well.
func TestMCPAggregatorToolCallsCountOnceAgainstTheProxysRateLimit(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = answering(`{"content":[]}`)
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	limited := func(apiID string) *APISpec {
		spec := remoteMCPProxyRuntimeSpec(apiID, orders.URL)
		spec.GlobalRateLimit = apidef.GlobalRateLimit{Rate: 10, Per: 60}
		return spec
	}
	ts.Gw.LoadAPI(
		limited("orders-mcp"),
		limited("orders-direct"),
		remoteMCPProxyRuntimeSpec("github-mcp", newMCPRoutingUpstream(t, namedTools("list_issues")...).URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	)
	key := companyToolsKey(t, ts)
	_, directKey := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.AccessRights = map[string]user.AccessDefinition{"orders-direct": {APIID: "orders-direct", APIName: "orders-direct"}}
	})

	firstRefused := func(call func() mcpTestResponse) (int, mcpTestResponse) {
		for i := 1; i <= 11; i++ {
			if res := call(); res.rpc.Error != nil {
				return i, res
			}
		}
		return 0, mcpTestResponse{}
	}
	direct, _ := firstRefused(func() mcpTestResponse {
		return postMCPToolsCallTo(t, ts, "/orders-direct/", directKey, toolCallParams("list_orders", `{}`, ""))
	})
	viaAggregator, refused := firstRefused(func() mcpTestResponse {
		return postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""))
	})

	require.NotZero(t, direct, "the direct calls were never rate-limited")
	assert.Equal(t, direct, viaAggregator, "the aggregator adds no request against the proxy's limit")
	require.NotNil(t, refused.rpc.Error)
	assert.Equal(t, jsonrpcerrors.CodeModernRateLimitExceeded, refused.rpc.Error.Code, "the orders chain refuses the call")
	assert.Equal(t, http.StatusOK, refused.status, "the proxy's 429 stays on the aggregator's hop")
	assert.Empty(t, orders.observed(mcp.MethodToolsList), "no tools/list is spent on resolving the calls")
}

func TestMCPAggregatorAnswersProxyJSONRPCErrorsWithHTTP200(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusBadRequest} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			proxyError := `{"code":-33001,"message":"<b>authentication required</b>","data":{"http_code":401}}`
			orders := newMCPRoutingUpstream(t, namedTools("create_order")...)
			orders.call = func(*http.Request, map[string]json.RawMessage) (string, int, string) {
				return "", status, `{"jsonrpc":"2.0","id":1,"error":` + proxyError + `}`
			}
			ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))

			res := postMCPToolsCall(t, ts, key, toolCallParams("orders__create_order", `{}`, ""))

			assert.Equal(t, http.StatusOK, res.status, res.body)
			assert.Empty(t, res.header.Get("WWW-Authenticate"))
			assert.Equal(t, `{"jsonrpc":"2.0","id":"call-1","error":`+proxyError+"}\n", res.body, "the error is kept byte for byte")
		})
	}
}

func TestMCPAggregatorRejectsAmbiguousToolNames(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders", "delete_all")...)
	orders.call = answering(`{"content":[]}`)
	ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`

	for name, params := range map[string]string{
		"duplicate name":     `{"name":"orders__delete_all","name":"orders__list_orders","arguments":{},` + meta + `}`,
		"case variant":       `{"name":"orders__list_orders","NAME":"delete_all","arguments":{},` + meta + `}`,
		"mixed-case variant": `{"Name":"delete_all","name":"orders__list_orders","arguments":{},` + meta + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			res := postMCPToolsCall(t, ts, key, params)

			assert.Equal(t, http.StatusBadRequest, res.status, res.body)
			require.NotNil(t, res.rpc.Error, res.body)
			assert.Equal(t, mcp.JSONRPCParseError, res.rpc.Error.Code, "ingress refuses it before the aggregator")
		})
	}
	assert.Empty(t, orders.observed(mcp.MethodToolsCall), "an ambiguous name is never forwarded")

	nested := postMCPToolsCall(t, ts, key, `{"name":"orders__list_orders","arguments":{"name":"orders__delete_all"},`+meta+`}`)
	require.Equal(t, http.StatusOK, nested.status, nested.body)
	calls := orders.observed(mcp.MethodToolsCall)
	require.Len(t, calls, 1)
	assert.JSONEq(t, `"list_orders"`, string(calls[0].Params["name"]))
	assert.JSONEq(t, `{"name":"orders__delete_all"}`, string(calls[0].Params["arguments"]), "only the top-level name is replaced")
}

func TestReplaceJSONObjectFieldFailsClosed(t *testing.T) {
	out, err := replaceJSONObjectField(json.RawMessage(`{ "a" : 1, "name" :  "x__y" ,"b":{"name":"z"}}`), "name", []byte(`"y"`))
	require.NoError(t, err)
	assert.Equal(t, `{ "a" : 1, "name" :  "y" ,"b":{"name":"z"}}`, string(out))

	for _, object := range []string{
		`{"name":"a","name":"b"}`,
		`{"name":"a","NAME":"b"}`,
		`{"Name":"a"}`,
		`{"arguments":{}}`,
		`["name"]`,
		`{"name":`,
	} {
		_, err := replaceJSONObjectField(json.RawMessage(object), "name", []byte(`"y"`))
		assert.Error(t, err, object)
	}
}

func TestMCPAggregatorPassesToolResultsThroughUnchanged(t *testing.T) {
	for name, result := range map[string]string{
		"tool error":         `{"content":[{"type":"text","text":"customer_id is required"}],"isError":true}`,
		"structured content": `{"content":[{"type":"text","text":"{\"orders\": []}"}],"structuredContent":{"orders":[]},"_meta":{"com.acme/page":1},"x-extension":{"kept":true}}`,
		"html-like text":     `{"content":[{"type":"text","text":"<b>a & b</b>"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			orders := newMCPRoutingUpstream(t, namedTools("create_order", "list_orders")...)
			orders.call = answering(result)
			ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))

			res := postMCPToolsCall(t, ts, key, toolCallParams("orders__create_order", `{}`, ""))

			require.Equal(t, http.StatusOK, res.status, res.body)
			assert.Equal(t, result, string(res.rpc.Result), "the result is returned byte for byte")
		})
	}
}

func TestMCPAggregatorPassesArgumentsAndMetadataThroughExactly(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("create_order")...)
	orders.call = answering(`{"content":[]}`)
	ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))
	arguments := `{"customer_id": "c-123", "items": [{"sku": "A1", "qty": 2}], "note": "<rush> & gift", "ratio": 1.50}`
	extraMeta := `"io.modelcontextprotocol/clientInfo":{"name":"acme-agent","version":"1.2.0"},"com.acme/trace-id":"t-789"`
	params := toolCallParams("orders__create_order", arguments, extraMeta)
	params = strings.Replace(params, `{"name"`, `{"com.acme/unknown":{"a":[1, 2]},"name"`, 1)

	res := postMCPToolsCall(t, ts, key, params, "Mcp-Param-Region", "eu-west")

	require.Equal(t, http.StatusOK, res.status, res.body)
	calls := orders.observed(mcp.MethodToolsCall)
	require.Len(t, calls, 1)
	assert.Equal(t, arguments, string(calls[0].Params["arguments"]), "arguments arrive byte for byte")
	var clientParams map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(params), &clientParams))
	assert.Equal(t, string(clientParams["_meta"]), string(calls[0].Params["_meta"]), "_meta arrives byte for byte")
	assert.Equal(t, `{"a":[1, 2]}`, string(calls[0].Params["com.acme/unknown"]), "unknown params are kept")
	assert.Equal(t, strings.Replace(params, `"orders__create_order"`, `"create_order"`, 1), extractParams(t, calls[0].Body), "only the name changes")
	assert.Equal(t, "eu-west", calls[0].Header.Get("Mcp-Param-Region"), "custom Mcp-Param headers are forwarded")
}

func extractParams(t *testing.T, body string) string {
	t.Helper()
	var envelope struct {
		Params json.RawMessage `json:"params"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &envelope))
	return string(envelope.Params)
}

func TestMCPAggregatorPassesToolCallErrorsOfTheProxyThrough(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("create_order")...)
	orders.call = func(*http.Request, map[string]json.RawMessage) (string, int, string) {
		return "", http.StatusOK, `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid arguments","data":{"field":"customer_id"}}}`
	}
	ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))

	res := postMCPToolsCall(t, ts, key, toolCallParams("orders__create_order", `{}`, ""))

	assert.Equal(t, http.StatusOK, res.status, res.body)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":"call-1","error":{"code":-32602,"message":"invalid arguments","data":{"field":"customer_id"}}}`, res.body)
}

func TestMCPAggregatorReportsAnUnavailableProxyOnlyForItsOwnTools(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = answering(`{"content":[{"type":"text","text":"0 orders"}]}`)
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	ts, key := startMCPAggregatorRoutingTest(t, orders, github)
	github.Close()
	hook := log.GetTestHook(t)

	res := postMCPToolsCall(t, ts, key, toolCallParams("github__list_issues", `{}`, ""))

	assert.Equal(t, http.StatusServiceUnavailable, res.status, res.body)
	require.NotNil(t, res.rpc.Error, res.body)
	assert.Equal(t, mcpAggregatorUpstreamErrorCode, res.rpc.Error.Code)
	assert.Equal(t, `upstream unavailable: aggregated MCP proxy "github"`, res.rpc.Error.Message)
	assert.Contains(t, res.body, `"id":"call-1"`)
	var warned bool
	for _, entry := range hook.AllEntries() {
		if entry.Message == mcpAggregatorToolCallFailedMsg && entry.Data["alias"] == "github" {
			warned = true
			assert.Equal(t, "github-mcp", entry.Data["upstream_api_id"])
			assert.Equal(t, "github__list_issues", entry.Data["tool"])
		}
	}
	assert.True(t, warned, "the failure is logged naming github")

	ok := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""))
	require.Equal(t, http.StatusOK, ok.status, ok.body)
	assert.JSONEq(t, `{"content":[{"type":"text","text":"0 orders"}]}`, string(ok.rpc.Result))
}

func TestMCPAggregatorReportsAnUnloadedProxyAsUnavailable(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("orders-mcp", orders.URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	)

	res := postMCPToolsCall(t, ts, key, toolCallParams("github__list_issues", `{}`, ""))

	assert.Equal(t, http.StatusServiceUnavailable, res.status, res.body)
	require.NotNil(t, res.rpc.Error, res.body)
	assert.Equal(t, `upstream unavailable: aggregated MCP proxy "github"`, res.rpc.Error.Message)
}

func TestMCPAggregatorToolCallsAreBlockedByTheConsumersToolRules(t *testing.T) {
	github := newMCPRoutingUpstream(t, namedTools("list_issues", "create_issue")...)
	github.call = answering(`{"content":[]}`)
	ts, _ := startMCPAggregatorRoutingTest(t, newMCPRoutingUpstream(t, namedTools("list_orders")...), github)
	key := companyToolsKeyWithTools(t, ts, user.AccessControlRules{Blocked: []string{"github__create_issue"}})

	blocked := postMCPToolsCall(t, ts, key, toolCallParams("github__create_issue", `{}`, ""))
	allowed := postMCPToolsCall(t, ts, key, toolCallParams("github__list_issues", `{}`, ""))

	assert.Equal(t, http.StatusForbidden, blocked.status, blocked.body)
	assert.Equal(t, http.StatusOK, allowed.status, allowed.body)
	require.Len(t, github.observed(mcp.MethodToolsCall), 1, "the blocked call never reaches the proxy")
}

func TestMCPAggregatorCallsToolsOnTheLatestVersion(t *testing.T) {
	github := newDualMCPUpstream(t, "list_issues")
	ts, key := startMCPAggregatorProtocolTest(t, github)

	res := postMCPToolsCall(t, ts, key, toolCallParams("github__list_issues", `{}`, ""))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assertMCPAggregatorCalledOnLatest(t, github, mcp.MethodToolsCall)
}
