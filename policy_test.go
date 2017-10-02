package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

func TestLoadPoliciesFromDashboardReLogin(t *testing.T) {
	// Mock Dashboard
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer ts.Close()

	oldUseDBAppConfigs := config.Global.UseDBAppConfigs
	config.Global.UseDBAppConfigs = false

	defer func() { config.Global.UseDBAppConfigs = oldUseDBAppConfigs }()

	allowExplicitPolicyID := config.Global.Policies.AllowExplicitPolicyID

	policyMap := LoadPoliciesFromDashboard(ts.URL, "", allowExplicitPolicyID)

	if policyMap != nil {
		t.Error("Should be nil because got back 403 from Dashboard")
	}
}
