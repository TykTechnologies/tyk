package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
)

func Test_BuildDashboardConnStr(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.DisableDashboardZeroConf = false
		globalConf.DBAppConfOptions.ConnectionString = ""
	})
	defer ts.Close()

	//we trigger a go routine here to simulate a redis zeroconf
	go func() {
		time.Sleep(1 * time.Second)
		cfg := ts.Gw.GetConfig()
		cfg.DBAppConfOptions.ConnectionString = "http://localhost"
		ts.Gw.SetConfig(cfg)
	}()

	connStr := ts.Gw.buildDashboardConnStr("/test")

	assert.Equal(t, connStr, "http://localhost/test")
}

func newTestDashboardHandler(t *testing.T, serverURL string) (*HTTPDashboardHandler, func()) {
	t.Helper()
	h, ts := newTestDashboardFixture(t, serverURL, nil)
	return h, ts.Close
}

// newTestDashboardFixture starts a test gateway wired to a stub Dashboard at
// serverURL and returns both the handler and the *Test so callers can load
// APIs/policies between requests. extraConf runs after the fixture defaults.
func newTestDashboardFixture(t *testing.T, serverURL string, extraConf func(c *config.Config)) (*HTTPDashboardHandler, *Test) {
	t.Helper()
	g := StartTest(func(c *config.Config) {
		c.UseDBAppConfigs = false
		c.NodeSecret = "test-secret"
		c.DBAppConfOptions.ConnectionTimeout = 2
		c.DisableDashboardZeroConf = true
		if extraConf != nil {
			extraConf(c)
		}
	})
	handler := &HTTPDashboardHandler{
		Gw:                      g.Gw,
		Secret:                  "test-secret",
		RegistrationEndpoint:    serverURL + "/register/node",
		HeartBeatEndpoint:       serverURL + "/register/ping",
		DeRegistrationEndpoint:  serverURL + "/system/node",
		KeyQuotaTriggerEndpoint: serverURL + "/system/key/quota_trigger",
	}
	g.Gw.DashService = handler
	return handler, g
}

func writeJSON(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("failed to write JSON response: %v", err)
	}
}

func writeBody(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	if _, err := w.Write([]byte(body)); err != nil {
		t.Errorf("failed to write response body: %v", err)
	}
}

func okResponse(nodeID, nonce string) NodeResponse {
	return NodeResponse{
		Status:  "OK",
		Message: map[string]any{"NodeID": nodeID},
		Nonce:   nonce,
	}
}

// TestRegister_Success verifies a 200 response sets NodeID and Nonce.
func TestRegister_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, okResponse("node-abc-123", "nonce-1"))
	}))
	defer srv.Close()

	h, close := newTestDashboardHandler(t, srv.URL)
	defer close()

	require.NoError(t, h.Register(context.Background()))

	assert.Equal(t, "node-abc-123", h.Gw.GetNodeID())

	h.Gw.ServiceNonceMutex.RLock()
	gotNonce := h.Gw.ServiceNonce
	h.Gw.ServiceNonceMutex.RUnlock()
	assert.Equal(t, "nonce-1", gotNonce)
}

// TestRegister_DuplicateSession409 verifies that a 409 with Status "OK" is treated as a
// successful registration — NodeID and Nonce are set and no retry is made.
// The old code returned nil on any 409 without reading the body, leaving NodeID and Nonce
// empty and causing the 403 -> 409 infinite loop.
func TestRegister_DuplicateSession409(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		writeJSON(t, w, okResponse("node-already-registered", "fresh-nonce-from-409"))
	}))
	defer srv.Close()

	h, close := newTestDashboardHandler(t, srv.URL)
	defer close()

	require.NoError(t, h.Register(context.Background()))

	assert.Equal(t, "node-already-registered", h.Gw.GetNodeID())

	h.Gw.ServiceNonceMutex.RLock()
	gotNonce := h.Gw.ServiceNonce
	h.Gw.ServiceNonceMutex.RUnlock()
	assert.Equal(t, "fresh-nonce-from-409", gotNonce)

	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount))
}

// retryTestHandler returns an httptest handler that responds with firstStatus/firstBody
// on the first call, then with a successful registration response on subsequent calls.
func retryTestHandler(t *testing.T, callCount *int32, firstStatus int, firstBody string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if atomic.AddInt32(callCount, 1) == 1 {
			w.WriteHeader(firstStatus)
			if firstBody != "" {
				if _, err := w.Write([]byte(firstBody)); err != nil {
					t.Errorf("failed to write response body: %v", err)
				}
			}
			return
		}
		writeJSON(t, w, okResponse("node-after-retry", "nonce-after-retry"))
	})
}

// TestRegister_Retries verifies that non-successful responses trigger a retry and the
// gateway correctly registers on the subsequent successful response.
func TestRegister_Retries(t *testing.T) {
	tests := []struct {
		name        string
		firstStatus int
		firstBody   string
	}{
		{
			name:        "lock contention 409",
			firstStatus: http.StatusConflict,
			firstBody:   `{"Status":"Error","Message":"Another registration operation in progress"}`,
		},
		{
			name:        "service unavailable 503",
			firstStatus: http.StatusServiceUnavailable,
			firstBody:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var callCount int32
			srv := httptest.NewServer(retryTestHandler(t, &callCount, tc.firstStatus, tc.firstBody))
			defer srv.Close()

			h, close := newTestDashboardHandler(t, srv.URL)
			defer close()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			require.NoError(t, h.Register(ctx))

			assert.Equal(t, "node-after-retry", h.Gw.GetNodeID())

			h.Gw.ServiceNonceMutex.RLock()
			gotNonce := h.Gw.ServiceNonce
			h.Gw.ServiceNonceMutex.RUnlock()
			assert.Equal(t, "nonce-after-retry", gotNonce)

			assert.Equal(t, int32(2), atomic.LoadInt32(&callCount))
		})
	}
}

func Test_parseRegistrationResponse(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		val        NodeResponse
		wantNodeID string
		wantOK     bool
	}{
		{
			name:       "200 with valid NodeID",
			statusCode: http.StatusOK,
			val:        NodeResponse{Status: "OK", Message: map[string]any{"NodeID": "node-1"}},
			wantNodeID: "node-1",
			wantOK:     true,
		},
		{
			name:       "409 with Status OK and valid NodeID",
			statusCode: http.StatusConflict,
			val:        NodeResponse{Status: "OK", Message: map[string]any{"NodeID": "node-already"}},
			wantNodeID: "node-already",
			wantOK:     true,
		},
		{
			name:       "409 with Status not OK triggers retry",
			statusCode: http.StatusConflict,
			val:        NodeResponse{Status: "Error", Message: "lock contention"},
			wantNodeID: "",
			wantOK:     false,
		},
		{
			name:       "non-map Message triggers retry",
			statusCode: http.StatusOK,
			val:        NodeResponse{Status: "OK", Message: "unexpected string"},
			wantNodeID: "",
			wantOK:     false,
		},
		{
			name:       "nil Message triggers retry",
			statusCode: http.StatusOK,
			val:        NodeResponse{Status: "OK", Message: nil},
			wantNodeID: "",
			wantOK:     false,
		},
		{
			name:       "map Message missing NodeID triggers retry",
			statusCode: http.StatusOK,
			val:        NodeResponse{Status: "OK", Message: map[string]any{"Other": "value"}},
			wantNodeID: "",
			wantOK:     false,
		},
		{
			name:       "map Message with empty NodeID triggers retry",
			statusCode: http.StatusOK,
			val:        NodeResponse{Status: "OK", Message: map[string]any{"NodeID": ""}},
			wantNodeID: "",
			wantOK:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotNodeID, gotOK := parseRegistrationResponse(tc.statusCode, tc.val)
			assert.Equal(t, tc.wantOK, gotOK)
			assert.Equal(t, tc.wantNodeID, gotNodeID)
		})
	}
}

func TestAttemptRegistration_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("not-valid-json"))
		require.NoError(t, err)
	}))
	defer srv.Close()

	h, close := newTestDashboardHandler(t, srv.URL)
	defer close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := h.Register(ctx)
	assert.Error(t, err)
}

func TestNewRequestWithContext_InvalidURL_Panics(t *testing.T) {
	h, close := newTestDashboardHandler(t, "http://localhost")
	defer close()

	assert.Panics(t, func() {
		h.newRequestWithContext(context.Background(), "INVALID METHOD", "://bad-url")
	})
}

// TestSendHeartBeat_Forbidden_ReRegisters verifies a 403 heartbeat triggers re-registration.
func TestSendHeartBeat_Forbidden_ReRegisters(t *testing.T) {
	var registerCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/register/ping":
			w.WriteHeader(http.StatusForbidden)
		case "/register/node":
			atomic.AddInt32(&registerCalls, 1)
			writeJSON(t, w, okResponse("node-recovered", "nonce-recovered"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	h, closeFn := newTestDashboardHandler(t, srv.URL)
	defer closeFn()

	err := h.sendHeartBeat(
		h.newRequest(http.MethodGet, h.HeartBeatEndpoint),
		h.Gw.initialiseClient(),
		context.Background())
	require.NoError(t, err)

	assert.Equal(t, int32(1), atomic.LoadInt32(&registerCalls))
	assert.Equal(t, "node-recovered", h.Gw.GetNodeID())

	h.Gw.ServiceNonceMutex.RLock()
	gotNonce := h.Gw.ServiceNonce
	h.Gw.ServiceNonceMutex.RUnlock()
	assert.Equal(t, "nonce-recovered", gotNonce)
}

// TestPing_HeartbeatOK_UpdatesNonce verifies a 200 heartbeat response stores the returned nonce.
func TestPing_HeartbeatOK_UpdatesNonce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, NodeResponse{Status: "OK", Nonce: "nonce-hb-1"})
	}))
	defer srv.Close()

	h, closeFn := newTestDashboardHandler(t, srv.URL)
	defer closeFn()

	require.NoError(t, h.Ping())

	h.Gw.ServiceNonceMutex.RLock()
	gotNonce := h.Gw.ServiceNonce
	h.Gw.ServiceNonceMutex.RUnlock()
	assert.Equal(t, "nonce-hb-1", gotNonce)
}

// TestPing_NilGatewayContext_DoesNotPanic guards against a nil gateway context.
func TestPing_NilGatewayContext_DoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, NodeResponse{Status: "OK", Nonce: "nonce-1"})
	}))
	defer srv.Close()

	h, closeFn := newTestDashboardHandler(t, srv.URL)
	defer closeFn()

	oldCtx := h.Gw.ctx
	h.Gw.ctx = nil
	defer func() { h.Gw.ctx = oldCtx }()

	assert.NotPanics(t, func() {
		assert.NoError(t, h.Ping())
	})
}

// TestPing_DashboardUnreachable_Fails verifies a transport error reports the dashboard as down.
func TestPing_DashboardUnreachable_Fails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.Close() // connection refused from now on

	h, closeFn := newTestDashboardHandler(t, srv.URL)
	defer closeFn()

	err := h.Ping()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dashboard is down? Heartbeat is failing")
}

// TestPing_RedisDownDashboardUp_DoesNotBlockOrReRegister is the TT-17486 regression test.
// With Redis down the Dashboard returns 403 on heartbeat and 409 on registration.
// Ping must return immediately without triggering re-registration.
func TestPing_RedisDownDashboardUp_DoesNotBlockOrReRegister(t *testing.T) {
	var registerAttempts int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/register/ping":
			// Dashboard with Redis down: GetNodeFromSessionWithFallback fails.
			w.WriteHeader(http.StatusForbidden)
			writeBody(t, w, `{"Status":"Error","Message":"Authorization failed (Session not found)"}`)
		case "/register/node":
			atomic.AddInt32(&registerAttempts, 1)
			// Dashboard with Redis down: NodeIDConn.Lock fails.
			w.WriteHeader(http.StatusConflict)
			writeBody(t, w, `{"Status":"Error","Message":"Another registration operation in progress"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	h, closeFn := newTestDashboardHandler(t, srv.URL)
	defer closeFn()

	done := make(chan error, 1)
	go func() {
		done <- h.Gw.DashService.Ping()
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
		assert.Zero(t, atomic.LoadInt32(&registerAttempts), "liveness probe must not trigger re-registration")
	case <-time.After(10 * time.Second):
		t.Fatalf("Ping() blocked after %d register attempts", atomic.LoadInt32(&registerAttempts))
	}
}

// TestPing_SlowDashboard_RedisDown_ReportsPass verifies that a slow but reachable
// Dashboard (Redis down, so its session lookup is delayed) returning 403 is
// reported as pass, not as dashboard down.
func TestPing_SlowDashboard_RedisDown_ReportsPass(t *testing.T) {
	const checkDuration = 4 * time.Second
	// Delay exceeds checkDuration/2 to simulate the Dashboard's internal Redis lookup latency.
	const dashDelay = checkDuration/2 + 500*time.Millisecond

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(dashDelay)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		writeBody(t, w, `{"Status":"Error","Message":"Authorization failed (Session not found)"}`)
	}))
	defer srv.Close()

	g := StartTest(func(c *config.Config) {
		c.UseDBAppConfigs = false
		c.NodeSecret = "test-secret"
		c.DisableDashboardZeroConf = true
		c.LivenessCheck.CheckDuration = checkDuration
	})
	defer g.Close()
	g.Gw.resetDashboardClient()
	t.Cleanup(g.Gw.resetDashboardClient)

	h := &HTTPDashboardHandler{
		Gw:                g.Gw,
		Secret:            "test-secret",
		HeartBeatEndpoint: srv.URL + "/register/ping",
	}
	g.Gw.DashService = h

	done := make(chan error, 1)
	go func() {
		done <- h.Ping()
	}()

	select {
	case err := <-done:
		assert.NoError(t, err, "slow 403 from dashboard must be treated as reachable (pass), not as dashboard down")
	case <-time.After(checkDuration * 2):
		t.Fatal("Ping() blocked: did not return within the expected window")
	}
}

func Test_DashboardLifecycle(t *testing.T) {
	var handler HTTPDashboardHandler

	handler = HTTPDashboardHandler{
		heartBeatStopSentinel: HeartBeatStarted,
	}
	assert.False(t, handler.isHeartBeatStopped())

	handler = HTTPDashboardHandler{
		heartBeatStopSentinel: HeartBeatStopped,
	}

	assert.True(t, handler.isHeartBeatStopped())

	handler = HTTPDashboardHandler{
		heartBeatStopSentinel: HeartBeatStarted,
	}

	handler.StopBeating()
	assert.True(t, handler.isHeartBeatStopped())
}

// dashboardStub is an httptest Dashboard that answers every call with a 200
// NodeResponse and records the last request headers it saw, per path.
type dashboardStub struct {
	URL  string
	mu   sync.Mutex
	seen map[string]http.Header
}

func newDashboardStub(t *testing.T) *dashboardStub {
	t.Helper()
	s := &dashboardStub{seen: map[string]http.Header{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen[r.URL.Path] = r.Header.Clone()
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, okResponse("node-meta", "nonce-meta"))
	}))
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	return s
}

func (s *dashboardStub) headers(t *testing.T, path string) http.Header {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Contains(t, s.seen, path, "no request captured for %s", path)
	return s.seen[path]
}

func assertNodeMetadataHeaders(t *testing.T, gw *Gateway, got http.Header, wantSegmented, wantTags, wantAPIs, wantPolicies string) {
	t.Helper()
	assert.Equal(t, VERSION, got.Get(header.XTykNodeVersion))
	assert.Equal(t, wantSegmented, got.Get(header.XTykNodeSegmented))
	if wantTags == "" {
		assert.NotContains(t, got, http.CanonicalHeaderKey(header.XTykNodeTags))
	} else {
		assert.Equal(t, wantTags, got.Get(header.XTykNodeTags))
	}
	assert.Equal(t, wantAPIs, got.Get(header.XTykAPIsCount))
	assert.Equal(t, wantPolicies, got.Get(header.XTykPoliciesCount))
	assert.Equal(t, strconv.Itoa(gw.hostDetails.PID), got.Get(header.XTykNodePID))
	assert.Equal(t, gw.hostDetails.Address, got.Get(header.XTykNodeAddress))
}

// TestRegister_SendsNodeMetadataHeaders: GET /register/node carries the node metadata.
func TestRegister_SendsNodeMetadataHeaders(t *testing.T) {
	dash := newDashboardStub(t)
	h, ts := newTestDashboardFixture(t, dash.URL, func(c *config.Config) {
		c.DBAppConfOptions.NodeIsSegmented = true
		c.DBAppConfOptions.Tags = []string{"reg-a", "reg-b"}
	})
	defer ts.Close()

	require.NoError(t, h.Register(context.Background()))
	assertNodeMetadataHeaders(t, ts.Gw, dash.headers(t, "/register/node"), "true", "reg-a,reg-b", "0", "0")
}

// TestHeartBeat_NodeMetadataHeadersRefreshOnReusedRequest: StartBeating builds
// one request and reuses it; every send must carry current counts. Ping() goes
// through the same path.
func TestHeartBeat_NodeMetadataHeadersRefreshOnReusedRequest(t *testing.T) {
	dash := newDashboardStub(t)
	h, ts := newTestDashboardFixture(t, dash.URL, nil)
	defer ts.Close()

	req := h.newRequest(http.MethodGet, h.HeartBeatEndpoint)
	client := h.Gw.initialiseClient()

	require.NoError(t, h.doHeartBeat(req, client))
	assertNodeMetadataHeaders(t, ts.Gw, dash.headers(t, "/register/ping"), "false", "", "0", "0")

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) { spec.Proxy.ListenPath = "/hb1/" },
		func(spec *APISpec) { spec.Proxy.ListenPath = "/hb2/" },
	)
	ts.CreatePolicy()

	require.NoError(t, h.doHeartBeat(req, client))
	assertNodeMetadataHeaders(t, ts.Gw, dash.headers(t, "/register/ping"), "false", "", "2", "1")

	require.NoError(t, h.Ping())
	assertNodeMetadataHeaders(t, ts.Gw, dash.headers(t, "/register/ping"), "false", "", "2", "1")
}

// TestDashboardRequests_OnlyKnownTykHeaders: register and heartbeat carry no
// x-tyk-* header beyond the known set, and never the MDCB api key.
func TestDashboardRequests_OnlyKnownTykHeaders(t *testing.T) {
	const mdcbKey = "mdcb-api-key-sentinel"
	dash := newDashboardStub(t)
	h, ts := newTestDashboardFixture(t, dash.URL, func(c *config.Config) {
		c.SlaveOptions.APIKey = mdcbKey
	})
	defer ts.Close()

	require.NoError(t, h.Register(context.Background()))
	require.NoError(t, h.Ping())

	allowed := append([]string{header.XTykNodeID, header.XTykSessionID, header.XTykNonce, header.XTykHostname}, nodeMetadataHeaderNames...)
	for _, path := range []string{"/register/node", "/register/ping"} {
		for name, values := range dash.headers(t, path) {
			if lower := strings.ToLower(name); strings.HasPrefix(lower, "x-tyk-") {
				assert.Contains(t, allowed, lower, "%s: unexpected header %q", path, name)
			}
			assert.NotContains(t, values, mdcbKey, "%s: header %q leaks the MDCB api key", path, name)
		}
	}
}

// TestDeRegisterAndQuotaTrigger_NoNodeMetadataHeaders: the headers are limited to register and heartbeat.
func TestDeRegisterAndQuotaTrigger_NoNodeMetadataHeaders(t *testing.T) {
	dash := newDashboardStub(t)
	h, ts := newTestDashboardFixture(t, dash.URL, func(c *config.Config) {
		c.DBAppConfOptions.Tags = []string{"never-sent"}
	})
	defer ts.Close()

	require.NoError(t, h.DeRegister())
	require.NoError(t, h.NotifyDashboardOfEvent(EventTriggerExceededMeta{
		OrgID: "default", Key: "k", TriggerLimit: 1, UsagePercentage: 100,
	}))

	for _, path := range []string{"/system/node", "/system/key/quota_trigger"} {
		got := dash.headers(t, path)
		for _, name := range nodeMetadataHeaderNames {
			assert.NotContains(t, got, http.CanonicalHeaderKey(name), "%s must not carry %s", path, name)
		}
	}
}
