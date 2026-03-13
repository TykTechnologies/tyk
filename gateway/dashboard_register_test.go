package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

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

func Test_DashboardRegister_DoReloadFails(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register/node":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(NodeResponseOK{
				Status: "OK",
				Message: map[string]string{
					"NodeID": "test-node-id",
				},
				Nonce: "test-nonce",
			})
		case "/system/policies":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		case "/system/apis":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = true
		globalConf.DBAppConfOptions.ConnectionString = mockServer.URL
		globalConf.NodeSecret = "test-secret"
	})
	defer ts.Close()

	// Reset the dashboard client so it uses the new config
	ts.Gw.resetDashboardClient()

	// Ensure performedSuccessfulReload is false initially
	ts.Gw.performedSuccessfulReload = false

	// Initialize the dashboard service
	dashboardServiceInit(ts.Gw)

	// Call gw.DashService.Register(context.Background())
	err := ts.Gw.DashService.Register(context.Background())

	// Assert that Register() returns nil (indicating success)
	assert.NoError(t, err)

	// Verify that the gateway did not successfully load APIs
	assert.False(t, ts.Gw.performedSuccessfulReload)
	assert.Equal(t, 0, ts.Gw.apisByIDLen())
}
