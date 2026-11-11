package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

// slowTool answers tools/call only after delay, unless the request is
// cancelled first; cancelled receives the time the upstream saw it go.
func slowTool(delay time.Duration, cancelled chan<- time.Time) func(*http.Request, map[string]json.RawMessage) (string, int, string) {
	return func(r *http.Request, _ map[string]json.RawMessage) (string, int, string) {
		select {
		case <-time.After(delay):
			return `{"content":[{"type":"text","text":"slow answer"}]}`, 0, ""
		case <-r.Context().Done():
			cancelled <- time.Now()
			return `{"content":[]}`, 0, ""
		}
	}
}

// toolsCallRequest is a 2026-07-28 tools/call request to company-tools.
func toolsCallRequest(t *testing.T, ctx context.Context, ts *Test, key, name string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/company-tools/", strings.NewReader(
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":`+toolCallParams(name, `{}`, "")+`}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(mcp.HeaderProtocolVersion, mcp.ModernProtocolVersion)
	req.Header.Set(mcp.HeaderMethod, mcp.MethodToolsCall)
	req.Header.Set(mcp.HeaderName, name)
	req.Header.Set("Authorization", key)
	return req
}

func TestMCPAggregatorCancelsTheUpstreamCallWhenTheAgentCancels(t *testing.T) {
	cancelled := make(chan time.Time, 1)
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = slowTool(30*time.Second, cancelled)
	ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	resp, err := http.DefaultClient.Do(toolsCallRequest(t, ctx, ts, key, "orders__list_orders"))
	if resp != nil {
		resp.Body.Close()
	}
	require.ErrorIs(t, err, context.Canceled, "the agent gave up before any result")

	select {
	case at := <-cancelled:
		assert.Less(t, at.Sub(start), 3*time.Second, "the upstream call is cancelled promptly")
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight call to the orders proxy was not cancelled")
	}
}

func TestMCPAggregatorSendsNoResultForACancelledCall(t *testing.T) {
	cancelled := make(chan time.Time, 1)
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = slowTool(30*time.Second, cancelled)
	ts, _ := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))
	mw := &MCPAggregatorMiddleware{BaseMiddleware: &BaseMiddleware{Spec: ts.Gw.getApiSpec("company-tools"), Gw: ts.Gw}}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/company-tools/", nil).WithContext(ctx)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodToolsCall, ID: 5, Params: json.RawMessage(toolCallParams("orders__list_orders", `{}`, "")),
	})
	time.AfterFunc(200*time.Millisecond, cancel)
	rec := httptest.NewRecorder()

	_, code := mw.ProcessRequest(rec, req, nil)

	assert.Equal(t, middleware.StatusRespond, code)
	assert.False(t, rec.Flushed)
	assert.Empty(t, rec.Body.String(), "nothing is written for a cancelled call")
	assert.Equal(t, http.StatusOK, rec.Code, "no status is written either")
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight call to the orders proxy was not cancelled")
	}
}

func TestMCPAggregatorCancellingOneCallLeavesTheOthersRunning(t *testing.T) {
	cancelled := make(chan time.Time, 1)
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = slowTool(30*time.Second, cancelled)
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	github.call = slowTool(700*time.Millisecond, make(chan time.Time, 1))
	ts, key := startMCPAggregatorRoutingTest(t, orders, github)

	ordersCtx, cancelOrders := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var githubStatus int
	var githubBody []byte
	var githubErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := http.DefaultClient.Do(toolsCallRequest(t, context.Background(), ts, key, "github__list_issues"))
		if err != nil {
			githubErr = err
			return
		}
		defer resp.Body.Close()
		githubStatus = resp.StatusCode
		githubBody, githubErr = io.ReadAll(resp.Body)
	}()
	time.AfterFunc(200*time.Millisecond, cancelOrders)
	_, ordersErr := http.DefaultClient.Do(toolsCallRequest(t, ordersCtx, ts, key, "orders__list_orders"))
	wg.Wait()

	require.ErrorIs(t, ordersErr, context.Canceled)
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the orders call was not cancelled")
	}
	require.NoError(t, githubErr)
	assert.Equal(t, http.StatusOK, githubStatus, string(githubBody))
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"slow answer"}]}}`, string(githubBody))
}

// withAggregatorTimeout sets the API-level enforced timeout, the
// upstream.enforceTimeout of the OAS definition, on every version.
func withAggregatorTimeout(spec *APISpec, timeout time.Duration) *APISpec {
	for name, version := range spec.VersionData.Versions {
		version.GlobalEnforceTimeout = tyktime.ReadableDuration(timeout)
		version.GlobalEnforceTimeoutDisabled = false
		spec.VersionData.Versions[name] = version
	}
	return spec
}

func TestMCPAggregatorTimesOutASlowToolCall(t *testing.T) {
	cancelled := make(chan time.Time, 1)
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = slowTool(30*time.Second, cancelled)
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("orders-mcp", orders.URL),
		remoteMCPProxyRuntimeSpec("github-mcp", github.URL),
		withAggregatorTimeout(companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")), time.Second),
	)
	hook := log.GetTestHook(t)

	start := time.Now()
	res := postMCPToolsCall(t, ts, companyToolsKey(t, ts), toolCallParams("orders__list_orders", `{}`, ""))
	elapsed := time.Since(start)

	assert.Equal(t, http.StatusGatewayTimeout, res.status, res.body)
	require.NotNil(t, res.rpc.Error, res.body)
	assert.Equal(t, mcpAggregatorUpstreamErrorCode, res.rpc.Error.Code)
	assert.Equal(t, `upstream timeout: aggregated MCP proxy "orders" did not answer within 1s`, res.rpc.Error.Message)
	assert.GreaterOrEqual(t, elapsed, time.Second)
	assert.Less(t, elapsed, 3*time.Second)
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the timed-out call to the orders proxy was not cancelled")
	}
	var warned bool
	for _, entry := range hook.AllEntries() {
		if entry.Message == mcpAggregatorToolCallFailedMsg && entry.Data["alias"] == "orders" {
			warned = true
			assert.Equal(t, "timeout after 1s", entry.Data["reason"])
		}
	}
	assert.True(t, warned)
}

func TestMCPAggregatorTimeoutBoundsAProxyThatIgnoresCancellation(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("orders-mcp", orders.URL),
		withAggregatorTimeout(companyToolsRuntimeSpec(aggregated("orders-mcp", "orders")), 500*time.Millisecond),
	)
	key := companyToolsKey(t, ts)

	// Replace the orders proxy chain with one that answers tools/list but never
	// returns from tools/call, whatever happens to its context.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	sawCancel := make(chan struct{}, 1)
	loaded, ok := ts.Gw.apisHandlesByID.Load("orders-mcp")
	require.True(t, ok)
	real := loaded.(*ChainObject).ThisHandler
	ts.Gw.apisHandlesByID.Store("orders-mcp", &ChainObject{ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(mcp.HeaderMethod) != mcp.MethodToolsCall {
			real.ServeHTTP(w, r)
			return
		}
		<-r.Context().Done()
		sawCancel <- struct{}{}
		<-release
	})})

	start := time.Now()
	res := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""))

	assert.Equal(t, http.StatusGatewayTimeout, res.status, res.body)
	assert.Less(t, time.Since(start), 3*time.Second, "the timeout is the final bound")
	select {
	case <-sawCancel:
	case <-time.After(time.Second):
		t.Fatal("the proxy's request context was not cancelled")
	}
}

func TestMCPAggregatorListOmitsAProxyThatExceedsTheTimeout(t *testing.T) {
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(10 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(slow.Close)
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("orders-mcp", slow.URL),
		remoteMCPProxyRuntimeSpec("github-mcp", github.URL),
		withAggregatorTimeout(companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")), 500*time.Millisecond),
	)
	hook := log.GetTestHook(t)

	start := time.Now()
	names, _ := mcpListedTools(t, postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, companyToolsKey(t, ts))))

	assert.Equal(t, []string{"github__list_issues"}, names)
	assert.Less(t, time.Since(start), 3*time.Second)
	warnings := mcpAggregatorOmissionWarnings(hook, "orders-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, "orders", warnings[0].Data["alias"])
}

func TestMCPAggregatorAcknowledgesCancelledNotifications(t *testing.T) {
	ts, key := startMCPAggregatorRoutingTest(t, newMCPRoutingUpstream(t, namedTools("list_orders")...), newMCPRoutingUpstream(t, namedTools("list_issues")...))

	call := modernCall(mcp.MethodNotificationsCancelled, key)
	call.notification = true
	res := postMCPTestCall(t, ts, "/company-tools/", call)

	assert.Equal(t, http.StatusAccepted, res.status, res.body)
	assert.Empty(t, res.body)
}

func TestMCPAggregatorUpstreamExchangeRecoversFromAPanickingChain(t *testing.T) {
	ts, _ := startMCPAggregatorRoutingTest(t, newMCPRoutingUpstream(t, namedTools("list_orders")...), newMCPRoutingUpstream(t, namedTools("list_issues")...))
	ts.Gw.apisHandlesByID.Store("orders-mcp", &ChainObject{ThisHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	})})
	d := mcpAggregatorDispatcher{gw: ts.Gw, aggregator: ts.Gw.getApiSpec("company-tools")}

	_, err := d.exchange(httptest.NewRequest(http.MethodPost, "/company-tools/", nil), ts.Gw.getApiSpec("orders-mcp"), mcp.MethodToolsList, []byte(`{}`), nil, nil)

	require.Error(t, err)
	assert.False(t, errors.Is(err, context.Canceled))
}
