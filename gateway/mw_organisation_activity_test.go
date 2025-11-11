//go:build !race || unstable
// +build !race unstable

package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/internal/uuid"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func (ts *Test) testPrepareProcessRequestQuotaLimit(tb testing.TB, data map[string]interface{}) {
	tb.Helper()
	// load API
	orgID := "test-org-" + uuid.New()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.OrgID = orgID
		spec.Proxy.ListenPath = "/"
	})

	data["org_id"] = orgID
	ts.Gw.StorageConnectionHandler.DisableStorage(true)
	expectBody := `{"status":"error","message":"Error writing to key store storage: Redis is either down or was not configured"}`
	// create org key with quota
	ts.Run(tb, test.TestCase{
		Path:      "/tyk/org/keys/" + orgID + "?reset_quota=1",
		AdminAuth: true,
		Method:    http.MethodPost,
		Data:      data,
		Code:      http.StatusInternalServerError,
		BodyMatch: expectBody,
	})
	ts.Gw.StorageConnectionHandler.DisableStorage(false)

	ts.Run(tb, test.TestCase{
		Path:      "/tyk/org/keys/" + orgID + "?reset_quota=1",
		AdminAuth: true,
		Method:    http.MethodPost,
		Code:      http.StatusOK,
		Data:      data,
	})
}

func TestOrganizationMonitorEnabled(t *testing.T) {
	test.Flaky(t) // Test uses StorageConnectionHandler (singleton).

	conf := func(globalConf *config.Config) {
		globalConf.EnforceOrgQuotas = true
		globalConf.ExperimentalProcessOrgOffThread = false
		globalConf.Monitor.EnableTriggerMonitors = true
		globalConf.Monitor.MonitorOrgKeys = true

	}
	ts := StartTest(conf)
	defer ts.Close()

	// load API
	ts.testPrepareProcessRequestQuotaLimit(
		t,
		map[string]interface{}{
			"quota_max":          10,
			"quota_remaining":    10,
			"quota_renewal_rate": 1,
		},
	)

	//check that the gateway is still up on request
	_, err := ts.Run(t, test.TestCase{
		Code: http.StatusOK,
	})
	if err != nil {
		t.Error("error running a gateway request when org is enabled")
	}
}

func TestProcessRequestLiveQuotaLimit(t *testing.T) {
	test.Flaky(t) // Test uses StorageConnectionHandler (singleton).

	conf := func(globalConf *config.Config) {
		globalConf.EnforceOrgQuotas = true
		globalConf.ExperimentalProcessOrgOffThread = false
	}
	ts := StartTest(conf)
	defer ts.Close()

	// load API
	ts.testPrepareProcessRequestQuotaLimit(
		t,
		map[string]interface{}{
			"quota_max":          10,
			"quota_remaining":    10,
			"quota_renewal_rate": 1,
		},
	)

	t.Run("Process request live with quota", func(t *testing.T) {
		// 1st ten requests within quota
		for i := 0; i < 10; i++ {
			ts.Run(t, test.TestCase{
				Code: http.StatusOK,
			})
		}
		// next request should fail with 403 as it is out of quota
		ts.Run(t, test.TestCase{
			Code: http.StatusForbidden,
		})

		// wait for renewal
		time.Sleep(2 * time.Second)

		// next one should be OK
		ts.Run(t, test.TestCase{
			Code: http.StatusOK,
		})
	})
}

func BenchmarkProcessRequestLiveQuotaLimit(b *testing.B) {
	b.ReportAllocs()

	conf := func(globalConf *config.Config) {
		globalConf.EnforceOrgQuotas = true
		globalConf.ExperimentalProcessOrgOffThread = false
	}

	ts := StartTest(conf)
	defer ts.Close()

	// setup global config
	globalConf := ts.Gw.GetConfig()

	ts.Gw.SetConfig(globalConf)

	// load API
	ts.testPrepareProcessRequestQuotaLimit(
		b,
		map[string]interface{}{
			"quota_max":          100000000,
			"quota_remaining":    100000000,
			"quota_renewal_rate": 300,
		},
	)

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: http.StatusOK,
		})
	}
}

func TestProcessRequestOffThreadQuotaLimit(t *testing.T) {
	test.Flaky(t) // Test uses StorageConnectionHandler (singleton).

	conf := func(globalConf *config.Config) {
		globalConf.EnforceOrgQuotas = true
		globalConf.ExperimentalProcessOrgOffThread = true
	}
	// run test server
	ts := StartTest(conf)
	defer ts.Close()

	// load API
	ts.testPrepareProcessRequestQuotaLimit(
		t,
		map[string]interface{}{
			"quota_max":          10,
			"quota_remaining":    10,
			"quota_renewal_rate": 2,
		},
	)

	t.Run("Process request off thread with quota", func(t *testing.T) {
		// at least first 10 requests within quota should be OK
		for i := 0; i < 10; i++ {
			ts.Run(t, test.TestCase{
				Code: http.StatusOK,
			})
		}

		// some of next request should fail with 403 as it is out of quota
		failed := false
		i := 0
		for i = 0; i < 11; i++ {
			res, _ := ts.Run(t, test.TestCase{})
			res.Body.Close()
			if res.StatusCode == http.StatusForbidden {
				failed = true
				break
			}
		}
		if !failed {
			t.Error("Requests don't fail after quota exceeded")
		} else {
			t.Logf("Failed with 403 after %d requests over quota", i)
		}

		// wait for renewal
		time.Sleep(4 * time.Second)

		// next 10 requests should be OK again
		ok := false
		for i = 0; i < 9; i++ {
			res, _ := ts.Run(t, test.TestCase{Delay: 10 * time.Millisecond})
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				ok = true
				break
			}
		}
		if !ok {
			t.Error("Requests still failing after quota renewal")
		} else {
			t.Logf("Started responding with 200 after %d requests after quota renewal", i)
		}
	})
}

func BenchmarkProcessRequestOffThreadQuotaLimit(b *testing.B) {
	b.ReportAllocs()

	// setup global config
	conf := func(globalConf *config.Config) {
		globalConf.EnforceOrgQuotas = true
		globalConf.ExperimentalProcessOrgOffThread = true
	}

	// run test server
	ts := StartTest(conf)
	defer ts.Close()

	// load API
	ts.testPrepareProcessRequestQuotaLimit(
		b,
		map[string]interface{}{
			"quota_max":          100000000,
			"quota_remaining":    100000000,
			"quota_renewal_rate": 300,
		},
	)

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: http.StatusOK,
		})
	}
}

func TestProcessRequestLiveRedisRollingLimiter(t *testing.T) {
	test.Flaky(t) // Test uses StorageConnectionHandler (singleton).

	ts := StartTest(nil)
	defer ts.Close()

	// setup global config
	globalConf := ts.Gw.GetConfig()
	globalConf.EnforceOrgQuotas = true
	globalConf.EnableRedisRollingLimiter = true
	globalConf.ExperimentalProcessOrgOffThread = false
	ts.Gw.SetConfig(globalConf)
	ts.Gw.DoReload()

	// load API
	ts.testPrepareProcessRequestQuotaLimit(
		t,
		map[string]interface{}{
			"quota_max": -1,
			"rate":      10,
			"per":       1,
		},
	)

	t.Run("Process request live with rate limit", func(t *testing.T) {
		// ten requests per sec should be OK
		for i := 0; i < 10; i++ {
			ts.Run(t, test.TestCase{
				Code: http.StatusOK,
			})
		}

		// wait for next time window
		time.Sleep(1 * time.Second)

		// try to run over rate limit
		reqNum := 1
		for {
			resp, _ := ts.Run(t, test.TestCase{})
			resp.Body.Close()
			if resp.StatusCode == http.StatusForbidden {
				break
			}
			reqNum++

			if reqNum > 20 {
				t.Errorf("Test takes too long to complete")
				break
			}
		}

		if reqNum < 10 {
			t.Errorf("Started failing too early after %d requests", reqNum)
		} else {
			t.Logf("Started failing after %d requests over limit", reqNum-10)
		}
	})
}

func BenchmarkProcessRequestLiveRedisRollingLimiter(b *testing.B) {
	b.ReportAllocs()

	conf := func(globalConf *config.Config) {
		globalConf.EnforceOrgQuotas = true
		globalConf.EnableRedisRollingLimiter = true
		globalConf.ExperimentalProcessOrgOffThread = false
	}

	// run test server
	ts := StartTest(conf)
	defer ts.Close()

	// load API
	ts.testPrepareProcessRequestQuotaLimit(
		b,
		map[string]interface{}{
			"quota_max": -1,
			"rate":      10000,
			"per":       1,
		},
	)

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: http.StatusOK,
		})
	}
}

func TestProcessRequestOffThreadRedisRollingLimiter(t *testing.T) {
	test.Flaky(t) // Test uses StorageConnectionHandler (singleton).

	// setup global config
	conf := func(globalConf *config.Config) {
		globalConf.EnforceOrgQuotas = true
		globalConf.EnableRedisRollingLimiter = true
		globalConf.ExperimentalProcessOrgOffThread = true
	}

	// run test server
	ts := StartTest(conf)
	defer ts.Close()

	// load API
	ts.testPrepareProcessRequestQuotaLimit(
		t,
		map[string]interface{}{
			"quota_max": -1,
			"rate":      10,
			"per":       1,
		},
	)

	t.Run("Process request off thread with rate limit", func(t *testing.T) {
		// ten requests per sec should be OK
		for i := 0; i < 10; i++ {
			ts.Run(t, test.TestCase{
				Code: http.StatusOK,
			})
		}

		// wait for next time window
		time.Sleep(2 * time.Second)

		// try to run over rate limit
		reqNum := 1
		for {
			resp, _ := ts.Run(t, test.TestCase{})
			resp.Body.Close()
			if resp.StatusCode == http.StatusForbidden {
				break
			}
			reqNum++
		}

		if reqNum < 10 {
			t.Errorf("Started failing too early after %d requests", reqNum)
		} else {
			t.Logf("Started failing after %d requests over limit", reqNum-10)
		}
	})
}

func BenchmarkProcessRequestOffThreadRedisRollingLimiter(b *testing.B) {
	b.ReportAllocs()

	// setup global config
	conf := func(globalConf *config.Config) {
		globalConf.EnforceOrgQuotas = true
		globalConf.EnableRedisRollingLimiter = true
		globalConf.ExperimentalProcessOrgOffThread = true
	}

	// run test server
	ts := StartTest(conf)
	defer ts.Close()

	// load API
	ts.testPrepareProcessRequestQuotaLimit(
		b,
		map[string]interface{}{
			"quota_max": -1,
			"rate":      10000,
			"per":       1,
		},
	)

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: http.StatusOK,
		})
	}
}

func TestOrganizationMonitor_RefreshOrgSession(t *testing.T) {
	conf := func(globalConf *config.Config) {
		globalConf.EnforceOrgQuotas = true
		globalConf.LocalSessionCache.DisableCacheSessionState = false
	}

	ts := StartTest(conf)
	defer ts.Close()

	orgID := "test-org-refresh-" + uuid.New()

	// Build API
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.OrgID = orgID
		spec.Proxy.ListenPath = "/"
	})

	t.Run("refreshOrgSession populates cache when session found", func(t *testing.T) {
		// Create org session
		ts.Run(t, test.TestCase{
			Path:      "/tyk/org/keys/" + orgID,
			AdminAuth: true,
			Method:    http.MethodPost,
			Code:      http.StatusOK,
			Data: map[string]interface{}{
				"quota_max":          10,
				"quota_remaining":    10,
				"quota_renewal_rate": 60,
			},
		})

		ts.Gw.SessionCache.Flush()

		// Verify cache is empty
		_, found := ts.Gw.SessionCache.Get(orgID)
		if found {
			t.Error("Cache should be empty")
		}

		spec := ts.Gw.apisByID[ts.Gw.apiSpecs[0].APIID]
		monitor := &OrganizationMonitor{
			BaseMiddleware: &BaseMiddleware{
				Spec: spec,
				Gw:   ts.Gw,
			},
		}

		// Call refreshOrgSession
		monitor.refreshOrgSession(orgID)

		// Wait a bit for async operation
		time.Sleep(50 * time.Millisecond)

		// Verify cache is now populated
		_, found = ts.Gw.SessionCache.Get(orgID)
		if !found {
			t.Error("Cache should be populated after refreshOrgSession")
		}
	})

	t.Run("refreshOrgSession sets OrgHasNoSession when session not found", func(t *testing.T) {
		nonExistentOrgID := "test-org-nonexistent-" + uuid.New()

		// Build API with non-existent org
		spec := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.OrgID = nonExistentOrgID
			spec.Proxy.ListenPath = "/nonexistent/"
		})[0]

		// Verify OrgHasNoSession is initially false
		if spec.OrgHasNoSession {
			t.Error("OrgHasNoSession should initially be false")
		}

		monitor := &OrganizationMonitor{
			BaseMiddleware: &BaseMiddleware{
				Spec: spec,
				Gw:   ts.Gw,
			},
		}

		monitor.refreshOrgSession(nonExistentOrgID)

		// Wait for async operation
		time.Sleep(50 * time.Millisecond)

		// Verify OrgHasNoSession is now true
		if !monitor.getOrgHasNoSession() {
			t.Error("OrgHasNoSession should be true after refreshOrgSession for non-existent org")
		}
	})
}
