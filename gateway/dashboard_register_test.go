package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
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
	conf := func(c *config.Config) {
		c.UseDBAppConfigs = false
		c.NodeSecret = "test-secret"
		c.DBAppConfOptions.ConnectionTimeout = 2
		c.DisableDashboardZeroConf = true
	}
	g := StartTest(conf)
	handler := &HTTPDashboardHandler{
		Gw:                   g.Gw,
		Secret:               "test-secret",
		RegistrationEndpoint: serverURL + "/register/node",
	}
	g.Gw.DashService = handler
	return handler, g.Close
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

// TestSendHeartBeat_Forbidden_ReRegisters pins the recovery path the health
// probe relies on: the heartbeat loop (not the probe) owns re-registration,
// so a 403 heartbeat response must trigger Register and refresh the node
// identity.
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
	h.HeartBeatEndpoint = srv.URL + "/register/ping"

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

// TestPing_HeartbeatOK_UpdatesNonce pins the healthy-path behaviour of the
// liveness probe: a 200 heartbeat response succeeds and stores the nonce
// returned by the dashboard.
func TestPing_HeartbeatOK_UpdatesNonce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, NodeResponse{Status: "OK", Nonce: "nonce-hb-1"})
	}))
	defer srv.Close()

	h, closeFn := newTestDashboardHandler(t, srv.URL)
	defer closeFn()
	h.HeartBeatEndpoint = srv.URL + "/register/ping"

	require.NoError(t, h.Ping())

	h.Gw.ServiceNonceMutex.RLock()
	gotNonce := h.Gw.ServiceNonce
	h.Gw.ServiceNonceMutex.RUnlock()
	assert.Equal(t, "nonce-hb-1", gotNonce)
}

// TestPing_NilGatewayContext_DoesNotPanic guards embedders that construct a
// Gateway without a context: the probe falls back to context.Background()
// instead of panicking in context.WithTimeout.
func TestPing_NilGatewayContext_DoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, NodeResponse{Status: "OK", Nonce: "nonce-1"})
	}))
	defer srv.Close()

	h, closeFn := newTestDashboardHandler(t, srv.URL)
	defer closeFn()
	h.HeartBeatEndpoint = srv.URL + "/register/ping"

	oldCtx := h.Gw.ctx
	h.Gw.ctx = nil
	defer func() { h.Gw.ctx = oldCtx }()

	assert.NotPanics(t, func() {
		assert.NoError(t, h.Ping())
	})
}

// TestPing_DashboardUnreachable_Fails pins the transport-error behaviour of
// the liveness probe: no response from the dashboard reports it as down.
func TestPing_DashboardUnreachable_Fails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.Close() // connection refused from now on

	h, closeFn := newTestDashboardHandler(t, srv.URL)
	defer closeFn()
	h.HeartBeatEndpoint = srv.URL + "/register/ping"

	err := h.Ping()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dashboard is down? Heartbeat is failing")
}

// TestPing_RedisDownDashboardUp_DoesNotBlockOrReRegister is the TT-17486
// regression test: with Redis down but the Dashboard up, the Dashboard
// answers the heartbeat with 403 (it cannot read the session->node mapping)
// and registration with 409 + Status "Error" (its Redis-backed lock/session
// calls fail). The liveness probe must not block on, nor trigger,
// re-registration in that state — Register() retries such a 409 every 5s
// until its context is cancelled, so a probe that reaches it wedges the
// health-check loop and /hello and /ready serve a stale "pass" cache.
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
	h.HeartBeatEndpoint = srv.URL + "/register/ping"

	done := make(chan error, 1)
	go func() {
		// Exactly what the dashboard goroutine in gatherHealthChecks does.
		done <- h.Gw.DashService.Ping()
	}()

	select {
	case err := <-done:
		// v5.8.13 parity: the dashboard responded (403), so it is reachable
		// and the probe reports it healthy without re-registering.
		require.NoError(t, err)
		assert.Zero(t, atomic.LoadInt32(&registerAttempts),
			"the liveness probe must never trigger node re-registration")
	case <-time.After(10 * time.Second):
		t.Fatalf("Ping() blocked (register attempts: %d) — the dashboard health "+
			"goroutine never finishes, gatherHealthChecks' wg.Wait() never returns, "+
			"and /hello and /ready serve the stale last-known-good status forever",
			atomic.LoadInt32(&registerAttempts))
	}
}

// TestPing_HangingDashboard_BoundedByTimeout verifies the probe is bounded by
// half the health-check interval: a dashboard that accepts the connection but
// never answers must be reported as failing before the round's barrier
// expires, not block the health-check loop.
func TestPing_HangingDashboard_BoundedByTimeout(t *testing.T) {
	const checkDuration = 4 * time.Second

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	// Production-default dashboard client (30s timeout) so the probe's own
	// bound is what gets exercised, not the test helper's short client.
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
	start := time.Now()
	go func() {
		done <- h.Gw.DashService.Ping()
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dashboard is down? Heartbeat is failing")
		// Mirror Ping's derivation, plus scheduling slack for slow CI. The
		// sum must stay strictly below checkDuration — the pre-fix
		// behaviour — so the assertion keeps distinguishing fixed from
		// unfixed code.
		probeTimeout := checkDuration / 2
		schedulingSlack := time.Second
		require.Less(t, probeTimeout+schedulingSlack, checkDuration)
		assert.Less(t, time.Since(start), probeTimeout+schedulingSlack,
			"the probe must time out at half the check interval so its error is reported before the round's barrier expires")
	case <-time.After(7 * time.Second):
		t.Fatal("Ping() not bounded: still blocked after 7s on an unresponsive dashboard")
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
