package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

func TestRegisterConflictDoesNotSetNonce(t *testing.T) {
	dashboard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"Status":"Error","Message":"Another registration operation in progress"}`))
	}))
	defer dashboard.Close()

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = false
		globalConf.NodeSecret = "test-secret"
		globalConf.DBAppConfOptions.ConnectionTimeout = 2
		globalConf.DisableDashboardZeroConf = true
	})
	defer ts.Close()

	ts.Gw.resetDashboardClient()
	ts.Gw.SessionID = "gw-session-conflict-only"
	initialNodeID := ts.Gw.GetNodeID()
	ts.Gw.ServiceNonce = "seed-nonce"

	handler := &HTTPDashboardHandler{
		Gw:                   ts.Gw,
		Secret:               "test-secret",
		RegistrationEndpoint: dashboard.URL + "/register/node",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	err := handler.Register(ctx)
	require.Error(t, err)

	// Conflict is not treated as success, and nonce/node are not updated.
	assert.Equal(t, initialNodeID, ts.Gw.GetNodeID())
	assert.Equal(t, "seed-nonce", ts.Gw.ServiceNonce)
}

func TestPolicyFetchRecoveryCannotRecoverWhenRegisterConflictReturnsNoNonce(t *testing.T) {
	var registerCalls int
	var policyCalls int

	dashboard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/register/node"):
			registerCalls++
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"Status":"Error","Message":"Another registration operation in progress"}`))
		case strings.Contains(r.URL.Path, "/system/policies"):
			policyCalls++
			if policyCalls == 1 {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"Status":"Error","Message":"Nonce failed"}`))
				return
			}
			if r.Header.Get("x-tyk-nonce") == "" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"Status":"Error","Message":"Authorization failed (Nonce empty)"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":[],"nonce":"new-nonce"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer dashboard.Close()

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.UseDBAppConfigs = false
		globalConf.NodeSecret = "test-secret"
		globalConf.DBAppConfOptions.ConnectionTimeout = 2
		globalConf.DisableDashboardZeroConf = true
	})
	defer ts.Close()

	ts.Gw.resetDashboardClient()
	ts.Gw.SetNodeID("node-before-recovery")
	ts.Gw.SessionID = "gw-session-recovery-loop"
	ts.Gw.ServiceNonce = ""
	ts.Gw.DashService = &HTTPDashboardHandler{
		Gw:                   ts.Gw,
		Secret:               "test-secret",
		RegistrationEndpoint: dashboard.URL + "/register/node",
	}

	policies, err := ts.Gw.LoadPoliciesFromDashboard(dashboard.URL+"/system/policies", "test-secret", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dashboard authentication failed")
	assert.Empty(t, policies)

	// executeDashboardRequestWithRecovery attempted recovery register(s) after first 403 nonce failure.
	assert.GreaterOrEqual(t, registerCalls, 1)
	// Once recovery fails, request returns the 403 auth failure without a second policy fetch.
	assert.Equal(t, 1, policyCalls)
	assert.Empty(t, ts.Gw.ServiceNonce)
}
