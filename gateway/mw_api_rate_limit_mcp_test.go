package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// mcpProxyKey returns a key with access to the given MCP proxy only.
func mcpProxyKey(t *testing.T, ts *Test, apiID string) string {
	t.Helper()
	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.AccessRights = map[string]user.AccessDefinition{apiID: {APIID: apiID, APIName: apiID}}
	})
	require.NotEmpty(t, key)
	return key
}

// assertAdmitsTenThenLimits sends 11 requests within the minute to an API
// limited to 10 per minute: the first ten pass and the eleventh is refused
// with HTTP 429 and the modern JSON-RPC rate-limit error.
func assertAdmitsTenThenLimits(t *testing.T, send func() mcpTestResponse) {
	t.Helper()
	for i := 1; i <= 10; i++ {
		res := send()
		require.Equal(t, http.StatusOK, res.status, "call %d: %s", i, res.body)
		require.Nil(t, res.rpc.Error, "call %d: %s", i, res.body)
	}
	res := send()
	assert.Equal(t, http.StatusTooManyRequests, res.status, res.body)
	require.NotNil(t, res.rpc.Error, res.body)
	assert.Equal(t, jsonrpcerrors.CodeModernRateLimitExceeded, res.rpc.Error.Code, res.body)
}

func withAPIRateLimit(spec *APISpec, rate, per float64) *APISpec {
	spec.GlobalRateLimit = apidef.GlobalRateLimit{Rate: rate, Per: per}
	return spec
}

func TestMCPProxyAPIRateLimitCountsEachRequestOnce(t *testing.T) {
	for _, method := range []string{mcp.MethodToolsCall, mcp.MethodToolsList} {
		t.Run(method, func(t *testing.T) {
			orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
			orders.call = answering(`{"content":[]}`)
			ts := startExactRateLimitTest(t)
			ts.Gw.LoadAPI(withAPIRateLimit(remoteMCPProxyRuntimeSpec("orders-mcp", orders.URL), 10, 60))
			key := mcpProxyKey(t, ts, "orders-mcp")

			assertAdmitsTenThenLimits(t, func() mcpTestResponse {
				if method == mcp.MethodToolsList {
					return postMCPTestCall(t, ts, "/orders-mcp/", modernCall(mcp.MethodToolsList, key))
				}
				return postMCPToolsCallTo(t, ts, "/orders-mcp/", key, toolCallParams("list_orders", `{}`, ""))
			})
		})
	}
}

// TestAPIToMCPProxyAPIRateLimitCountsEachRequestOnce covers an API-to-MCP
// proxy as /tyk/mcps stores it: not flagged as an MCP API, so its requests
// never take JSON-RPC VEM hops and its rate-limit error is the gateway's
// generic one.
func TestAPIToMCPProxyAPIRateLimitCountsEachRequestOnce(t *testing.T) {
	ts, _, ordersBackend := startMCPAggregatorRuntimeTestWith(t)
	proxy := withAPIRateLimit(ordersMCPProxyRuntimeSpec(), 10, 60)
	require.False(t, proxy.IsMCP())
	ts.Gw.LoadAPI(ordersRESTSourceSpec(ordersBackend.URL, false), proxy)
	key := mcpProxyKey(t, ts, "orders-mcp")

	for i := 1; i <= 10; i++ {
		res := postMCPToolsCallTo(t, ts, "/orders-mcp/", key, toolCallParams("list_orders", `{}`, ""))
		require.Equal(t, http.StatusOK, res.status, "call %d: %s", i, res.body)
	}
	res := postMCPToolsCallTo(t, ts, "/orders-mcp/", key, toolCallParams("list_orders", `{}`, ""))
	assert.Equal(t, http.StatusTooManyRequests, res.status, res.body)
}

// TestAPIRateLimitStillCountsLoopsOutsideMCPRouting checks that only an MCP
// API's own JSON-RPC VEM hops skip its API-wide bucket: a classic loop with
// check_limits, on an MCP API or not, still spends it, and so does a loop
// carrying another API's routing state.
func TestAPIRateLimitStillCountsLoopsOutsideMCPRouting(t *testing.T) {
	// The default limiter keys each limiter's bucket by its load time, so the
	// unloaded limiters below start empty on every run.
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	limiter := func(apiID string, mcpAPI bool) *RateLimitForAPI {
		def := &apidef.APIDefinition{APIID: apiID, OrgID: mcpAggregatorRuntimeOrg, GlobalRateLimit: apidef.GlobalRateLimit{Rate: 1, Per: 60}}
		def.VersionData.NotVersioned = true
		def.VersionData.Versions = map[string]apidef.VersionInfo{"Default": {Name: "Default"}}
		if mcpAPI {
			def.MarkAsMCP()
		}
		rl := &RateLimitForAPI{BaseMiddleware: &BaseMiddleware{Spec: &APISpec{APIDefinition: def}, Gw: ts.Gw}}
		require.True(t, rl.EnabledForSpec())
		return rl
	}
	// loop returns a looping request carrying the JSON-RPC routing state of
	// routedBy, or none when routedBy is empty.
	loop := func(routedBy string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		httpctx.SetSelfLooping(r, true)
		ctxSetCheckLoopLimits(r, true)
		if routedBy != "" {
			httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{APIID: routedBy, Method: mcp.MethodToolsCall})
		}
		return r
	}
	status := func(rl *RateLimitForAPI, r *http.Request) int {
		_, code := rl.ProcessRequest(httptest.NewRecorder(), r, nil)
		return code
	}

	for name, tc := range map[string]struct {
		mcpAPI   bool
		routedBy string
	}{
		"non-MCP API, classic loop":                          {},
		"non-MCP API, loop with its own routing state":       {routedBy: "self"},
		"MCP API, classic loop":                              {mcpAPI: true},
		"MCP API, loop carrying another API's routing state": {mcpAPI: true, routedBy: "front-mcp"},
	} {
		t.Run(name, func(t *testing.T) {
			apiID := "loop-" + strings.ReplaceAll(name, " ", "-")
			routedBy := tc.routedBy
			if routedBy == "self" {
				routedBy = apiID
			}
			rl := limiter(apiID, tc.mcpAPI)
			assert.Equal(t, http.StatusOK, status(rl, loop(routedBy)))
			assert.Equal(t, http.StatusTooManyRequests, status(rl, loop(routedBy)), "the loop spends the API-wide bucket")
		})
	}
	t.Run("MCP API, its own JSON-RPC VEM hop", func(t *testing.T) {
		rl := limiter("loop-mcp-vem", true)
		assert.Equal(t, http.StatusOK, status(rl, httptest.NewRequest(http.MethodPost, "/", nil)))
		assert.Equal(t, http.StatusOK, status(rl, loop("loop-mcp-vem")), "the hop does not spend the API-wide bucket again")
		assert.Equal(t, http.StatusTooManyRequests, status(rl, httptest.NewRequest(http.MethodPost, "/", nil)))
	})
}

// TestChainedMCPProxyStillSpendsTheNextProxysAPILimit checks that a request
// looping from one MCP proxy into another through tyk://<api> spends the
// second proxy's API-wide limit: the first proxy's JSON-RPC routing does not
// make the second proxy's passes look like its own VEM hops.
func TestChainedMCPProxyStillSpendsTheNextProxysAPILimit(t *testing.T) {
	for name, target := range map[string]string{
		"loop":             "tyk://back-mcp",
		"loop with limits": "tyk://back-mcp/?check_limits=true",
	} {
		t.Run(name, func(t *testing.T) {
			back := newMCPRoutingUpstream(t, namedTools("list_orders")...)
			back.call = answering(`{"content":[]}`)
			ts := startExactRateLimitTest(t)
			ts.Gw.LoadAPI(
				remoteMCPProxyRuntimeSpec("front-mcp", target),
				withAPIRateLimit(remoteMCPProxyRuntimeSpec("back-mcp", back.URL), 3, 60),
			)
			_, key := ts.CreateSession(func(s *user.SessionState) {
				s.OrgID = mcpAggregatorRuntimeOrg
				s.AccessRights = map[string]user.AccessDefinition{
					"front-mcp": {APIID: "front-mcp", APIName: "front-mcp"},
					"back-mcp":  {APIID: "back-mcp", APIName: "back-mcp"},
				}
			})

			for i := 1; i <= 3; i++ {
				res := postMCPToolsCallTo(t, ts, "/front-mcp/", key, toolCallParams("list_orders", `{}`, ""))
				require.Equal(t, http.StatusOK, res.status, "call %d: %s", i, res.body)
				require.Nil(t, res.rpc.Error, "call %d: %s", i, res.body)
			}
			fourth := postMCPToolsCallTo(t, ts, "/front-mcp/", key, toolCallParams("list_orders", `{}`, ""))

			assert.Equal(t, http.StatusTooManyRequests, fourth.status, fourth.body)
			require.NotNil(t, fourth.rpc.Error, fourth.body)
			assert.Equal(t, jsonrpcerrors.CodeModernRateLimitExceeded, fourth.rpc.Error.Code)
			assert.Equal(t, 3, len(back.observed(mcp.MethodToolsCall)), "the refused call never reaches back's upstream")
		})
	}
}

// TestChainedMCPProxyStillSpendsTheKeysLimitOnTheNextProxy is the key-level
// counterpart: the consumer's per-API rate limit on the second proxy still
// applies to requests looping into it from another MCP proxy.
func TestChainedMCPProxyStillSpendsTheKeysLimitOnTheNextProxy(t *testing.T) {
	back := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	back.call = answering(`{"content":[]}`)
	ts := startExactRateLimitTest(t)
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("front-mcp", "tyk://back-mcp"),
		remoteMCPProxyRuntimeSpec("back-mcp", back.URL),
	)
	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.Rate, s.Per = 1000, 1
		s.AccessRights = map[string]user.AccessDefinition{
			"front-mcp": {APIID: "front-mcp", APIName: "front-mcp"},
			"back-mcp":  {APIID: "back-mcp", APIName: "back-mcp", Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 3, Per: 60}}},
		}
	})

	for i := 1; i <= 3; i++ {
		res := postMCPToolsCallTo(t, ts, "/front-mcp/", key, toolCallParams("list_orders", `{}`, ""))
		require.Equal(t, http.StatusOK, res.status, "call %d: %s", i, res.body)
	}
	fourth := postMCPToolsCallTo(t, ts, "/front-mcp/", key, toolCallParams("list_orders", `{}`, ""))

	assert.Equal(t, http.StatusTooManyRequests, fourth.status, fourth.body)
	assert.Equal(t, 3, len(back.observed(mcp.MethodToolsCall)))
}

// versionedMCPProxy returns base-mcp, an MCP proxy whose version v2 is the
// child API child-mcp, selected by the x-api-version header.
func versionedMCPProxy(upstreamURL string) (base, child *APISpec) {
	baseDoc := mcpRuntimeDoc("base-mcp", upstreamURL)
	baseDoc.GetTykExtension().Info.Versioning = &oas.Versioning{
		Enabled: true, Name: "v1", Default: "v1", Location: "header", Key: "x-api-version",
		Versions: []oas.VersionToID{{Name: "v2", ID: "child-mcp"}},
	}
	base = requireToken(mcpRuntimeOASSpec(baseDoc, true))
	child = requireToken(mcpRuntimeOASSpec(mcpRuntimeDoc("child-mcp", upstreamURL), true))
	child.VersionDefinition.BaseID = "base-mcp"
	return base, child
}

// TestVersionedMCPProxyCountsEachRequestOnce checks that a tools/call reaching
// a child version through its base API spends the key's rate limit, the key's
// quota and the child's API-level limit once: the child's JSON-RPC VEM hops
// are its own, although the base planned the routing.
func TestVersionedMCPProxyCountsEachRequestOnce(t *testing.T) {
	for name, tc := range map[string]struct {
		session  func(*user.SessionState)
		apiLimit bool
	}{
		"key rate limit": {session: func(s *user.SessionState) { s.Rate, s.Per = 3, 60 }},
		"key quota": {session: func(s *user.SessionState) {
			s.Rate, s.Per = 1000, 1
			s.QuotaMax, s.QuotaRemaining, s.QuotaRenewalRate = 3, 3, 3600
		}},
		"API-level limit": {session: func(s *user.SessionState) { s.Rate, s.Per = 1000, 1 }, apiLimit: true},
	} {
		t.Run(name, func(t *testing.T) {
			upstream := newMCPRoutingUpstream(t, namedTools("list_orders")...)
			upstream.call = answering(`{"content":[]}`)
			ts := startExactRateLimitTest(t)
			base, child := versionedMCPProxy(upstream.URL)
			if tc.apiLimit {
				child = withAPIRateLimit(child, 3, 60)
			}
			ts.Gw.LoadAPI(base, child)
			_, key := ts.CreateSession(func(s *user.SessionState) {
				s.OrgID = mcpAggregatorRuntimeOrg
				tc.session(s)
				s.AccessRights = map[string]user.AccessDefinition{
					"base-mcp":  {APIID: "base-mcp", APIName: "base-mcp"},
					"child-mcp": {APIID: "child-mcp", APIName: "child-mcp"},
				}
			})

			for i := 1; i <= 3; i++ {
				res := postMCPToolsCallTo(t, ts, "/base-mcp/", key, toolCallParams("list_orders", `{}`, ""), "x-api-version", "v2")
				require.Equal(t, http.StatusOK, res.status, "call %d: %s", i, res.body)
				require.Nil(t, res.rpc.Error, "call %d: %s", i, res.body)
			}
			fourth := postMCPToolsCallTo(t, ts, "/base-mcp/", key, toolCallParams("list_orders", `{}`, ""), "x-api-version", "v2")

			require.NotNil(t, fourth.rpc.Error, fourth.body)
			assert.Equal(t, 3, len(upstream.observed(mcp.MethodToolsCall)), "each admitted call reaches the child's upstream once")
		})
	}
}

// startExactRateLimitTest starts a gateway with the Redis rolling limiter,
// which counts every request exactly, so tests can assert the call a limit
// refuses; the default limiter is approximate. Its API-level windows live in
// Redis under the API's ID, so they are removed when the test ends, before
// another test or run loads an API with the same ID.
func startExactRateLimitTest(t *testing.T, conf ...func(*config.Config)) *Test {
	t.Helper()
	ts := StartTest(func(c *config.Config) {
		c.EnableRedisRollingLimiter = true
		for _, f := range conf {
			f(c)
		}
	})
	t.Cleanup(ts.Close)
	t.Cleanup(func() { clearAPIRateLimitWindows(t, ts) })
	return ts
}

// clearAPIRateLimitWindows deletes the Redis rolling windows of the loaded
// APIs' API-level rate limits.
func clearAPIRateLimitWindows(t *testing.T, ts *Test) {
	t.Helper()
	ts.Gw.apisMu.RLock()
	keys := make([]string, 0, len(ts.Gw.apisByID))
	for _, spec := range ts.Gw.apisByID {
		hash := storage.HashKey("apilimiter-"+spec.OrgID+spec.APIID, ts.Gw.GetConfig().HashKeys)
		keys = append(keys, rate.Prefix(rate.LimiterKeyPrefix, hash))
	}
	ts.Gw.apisMu.RUnlock()
	if len(keys) > 0 && ts.Gw.SessionLimiter.limiterStorage != nil {
		require.NoError(t, ts.Gw.SessionLimiter.limiterStorage.Del(context.Background(), keys...).Err())
	}
}

// startMCPAggregatorRuntimeTestWith is startMCPAggregatorRuntimeTest on a
// gateway from startExactRateLimitTest.
func startMCPAggregatorRuntimeTestWith(t *testing.T, conf ...func(*config.Config)) (*Test, *mockRemoteMCPServer, *httptest.Server) {
	t.Helper()
	ts := startExactRateLimitTest(t, conf...)
	github := newMockRemoteMCPServer(t, "search_repos", "create_issue")
	ordersBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(ordersBackend.Close)
	return ts, github, ordersBackend
}
