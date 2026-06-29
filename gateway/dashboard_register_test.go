package gateway

import (
	"context"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestRegister_SingleflightSharesInFlightRegistration(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	var callCount int32

	h := newClientBackedDashboardHandler(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		atomic.AddInt32(&callCount, 1)
		startOnce.Do(func() { close(started) })
		<-release

		return dashboardHTTPResponse(http.StatusOK, `{"Status":"OK","Message":{"NodeID":"node-singleflight"},"Nonce":"nonce-singleflight"}`), nil
	}))

	errs := make(chan error, 2)
	go func() { errs <- h.Register(context.Background()) }()

	waitForSignal(t, started, "first Register() request to reach dashboard")

	go func() { errs <- h.Register(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	close(release)

	for i := 0; i < 2; i++ {
		require.NoError(t, <-errs)
	}

	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount))
	assert.Equal(t, "node-singleflight", h.Gw.GetNodeID())
}

func TestRegister_SingleflightContinuesAfterCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	var callCount int32

	h := newClientBackedDashboardHandler(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		atomic.AddInt32(&callCount, 1)
		startOnce.Do(func() { close(started) })
		<-release

		return dashboardHTTPResponse(http.StatusOK, `{"Status":"OK","Message":{"NodeID":"node-after-cancelled-waiter"},"Nonce":"nonce-after-cancelled-waiter"}`), nil
	}))

	ctx, cancel := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() { firstErr <- h.Register(ctx) }()

	waitForSignal(t, started, "first Register() request to reach dashboard")
	cancel()

	require.ErrorIs(t, <-firstErr, context.Canceled)

	secondErr := make(chan error, 1)
	go func() { secondErr <- h.Register(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	close(release)

	require.NoError(t, <-secondErr)
	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount))
	assert.Equal(t, "node-after-cancelled-waiter", h.Gw.GetNodeID())
}

func TestRegister_StopsWhenGatewayLifecycleContextIsCancelled(t *testing.T) {
	lifecycleCtx, cancel := context.WithCancel(context.Background())
	cancel()

	gw := NewGateway(config.Config{
		NodeSecret: "test-secret",
		DBAppConfOptions: config.DBAppConfOptionsConfig{
			ConnectionTimeout: 1,
		},
	}, lifecycleCtx)
	gw.SessionID = "shutdown-session"

	h := &HTTPDashboardHandler{
		Gw:                   gw,
		Secret:               "test-secret",
		RegistrationEndpoint: "http://127.0.0.1:1/register/node",
	}

	err := h.Register(context.Background())
	require.ErrorIs(t, err, context.Canceled)
}

func TestAttemptRegistration_EmptyNonceKeepsExistingState(t *testing.T) {
	h := newClientBackedDashboardHandler(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return dashboardHTTPResponse(http.StatusOK, `{"Status":"OK","Message":{"NodeID":"node-from-empty-nonce-response"},"Nonce":""}`), nil
	}))

	h.Gw.SetNodeID("existing-node")
	h.Gw.ServiceNonceMutex.Lock()
	h.Gw.ServiceNonce = "existing-nonce"
	h.Gw.ServiceNonceMutex.Unlock()

	registered, err := h.attemptRegistration(context.Background())
	require.NoError(t, err)
	assert.False(t, registered)
	assert.Equal(t, "existing-node", h.Gw.GetNodeID())

	h.Gw.ServiceNonceMutex.RLock()
	gotNonce := h.Gw.ServiceNonce
	h.Gw.ServiceNonceMutex.RUnlock()
	assert.Equal(t, "existing-nonce", gotNonce)
}

func TestSendHeartBeat_EmptyNonceKeepsExistingNonce(t *testing.T) {
	h := newClientBackedDashboardHandler(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return dashboardHTTPResponse(http.StatusOK, `{"Status":"OK","Nonce":""}`), nil
	}))

	h.Gw.ServiceNonceMutex.Lock()
	h.Gw.ServiceNonce = "existing-heartbeat-nonce"
	h.Gw.ServiceNonceMutex.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := h.newRequest(http.MethodGet, "http://dashboard.local/register/ping")
	err := h.sendHeartBeat(req, h.Gw.initialiseClient(), ctx)
	require.ErrorIs(t, err, context.Canceled)

	h.Gw.ServiceNonceMutex.RLock()
	gotNonce := h.Gw.ServiceNonce
	h.Gw.ServiceNonceMutex.RUnlock()
	assert.Equal(t, "existing-heartbeat-nonce", gotNonce)
}

func TestDeRegister_EmptyNonceKeepsExistingNonce(t *testing.T) {
	h := newClientBackedDashboardHandler(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return dashboardHTTPResponse(http.StatusOK, `{"Status":"OK","Nonce":""}`), nil
	}))

	h.Gw.SetNodeID("node-for-deregister")
	h.Gw.ServiceNonceMutex.Lock()
	h.Gw.ServiceNonce = "existing-deregister-nonce"
	h.Gw.ServiceNonceMutex.Unlock()

	require.NoError(t, h.DeRegister())

	h.Gw.ServiceNonceMutex.RLock()
	gotNonce := h.Gw.ServiceNonce
	h.Gw.ServiceNonceMutex.RUnlock()
	assert.Equal(t, "existing-deregister-nonce", gotNonce)
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

func TestNextRegisterRetryDelay(t *testing.T) {
	testCases := []struct {
		name    string
		attempt int
		min     time.Duration
		max     time.Duration
	}{
		{name: "attempt 1", attempt: 1, min: 5 * time.Second, max: 6500 * time.Millisecond},
		{name: "attempt 2", attempt: 2, min: 10 * time.Second, max: 11500 * time.Millisecond},
		{name: "attempt 5 capped", attempt: 5, min: 60 * time.Second, max: 60 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &HTTPDashboardHandler{retryRng: rand.New(rand.NewSource(1))}
			delay := h.nextRegisterRetryDelay(tc.attempt)
			assert.GreaterOrEqual(t, delay, tc.min)
			assert.LessOrEqual(t, delay, tc.max)
		})
	}
}

func TestForbiddenRecoveryPlan_ResetAndMetric(t *testing.T) {
	now := time.Unix(1700000000, 0)
	h := &HTTPDashboardHandler{
		Gw:       &Gateway{},
		now:      func() time.Time { return now },
		retryRng: rand.New(rand.NewSource(42)),
	}
	h.Gw.SetNodeID("node-1")

	originalMetricRecorder := recordReRegisterCircuitOpenMetric
	t.Cleanup(func() {
		recordReRegisterCircuitOpenMetric = originalMetricRecorder
	})

	var metricCalls int
	var metricNodeID string
	var metricConsecutive int
	var metricDelay time.Duration
	recordReRegisterCircuitOpenMetric = func(nodeID string, consecutive int, delay time.Duration) {
		metricCalls++
		metricNodeID = nodeID
		metricConsecutive = consecutive
		metricDelay = delay
	}

	firstDelay, firstConsecutive := h.nextForbiddenRecoveryPlan()
	require.Equal(t, 1, firstConsecutive)
	assert.GreaterOrEqual(t, firstDelay, time.Second)
	assert.LessOrEqual(t, firstDelay, 5*time.Second)

	h.recordReRegisterCircuitOpen(firstConsecutive, firstDelay)
	assert.Equal(t, 0, metricCalls)

	now = now.Add(10 * time.Second)
	secondDelay, secondConsecutive := h.nextForbiddenRecoveryPlan()
	require.Equal(t, 2, secondConsecutive)
	assert.GreaterOrEqual(t, secondDelay, 2*time.Second)
	assert.LessOrEqual(t, secondDelay, 60*time.Second)

	h.recordReRegisterCircuitOpen(secondConsecutive, secondDelay)
	require.Equal(t, 1, metricCalls)
	assert.Equal(t, "node-1", metricNodeID)
	assert.Equal(t, 2, metricConsecutive)
	assert.Equal(t, secondDelay, metricDelay)

	h.resetForbiddenRecoveryState()
	now = now.Add(time.Second)
	_, consecutiveAfterReset := h.nextForbiddenRecoveryPlan()
	assert.Equal(t, 1, consecutiveAfterReset)
}

func TestSleepWithContext(t *testing.T) {
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := sleepWithContext(ctx, 5*time.Second)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("non-positive delay", func(t *testing.T) {
		err := sleepWithContext(context.Background(), 0)
		require.NoError(t, err)

		err = sleepWithContext(context.Background(), -1*time.Second)
		require.NoError(t, err)
	})
}

func waitForSignal(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newClientBackedDashboardHandler(t *testing.T, rt http.RoundTripper) *HTTPDashboardHandler {
	t.Helper()

	gw := NewGateway(config.Config{
		NodeSecret:               "test-secret",
		DisableDashboardZeroConf: true,
		DBAppConfOptions: config.DBAppConfOptionsConfig{
			ConnectionTimeout: 1,
		},
	}, context.Background())
	gw.SessionID = "unit-test-session"
	gw.resetDashboardClient()

	dashClient = &http.Client{
		Transport: rt,
		Timeout:   time.Second,
	}
	t.Cleanup(func() {
		gw.resetDashboardClient()
	})

	handler := &HTTPDashboardHandler{
		Gw:                     gw,
		Secret:                 "test-secret",
		RegistrationEndpoint:   "http://dashboard.local/register/node",
		DeRegistrationEndpoint: "http://dashboard.local/register/node",
	}
	gw.DashService = handler

	return handler
}

func dashboardHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
