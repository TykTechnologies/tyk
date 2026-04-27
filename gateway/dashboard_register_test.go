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
