package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/test"
)

func TestReloadLoop_basic(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()
	var n atomic.Value
	add := func() {
		if x := n.Load(); x != nil {
			n.Store(x.(int) + 1)
		} else {
			n.Store(int(0))
		}
	}

	ts.Gw.reloadURLStructure(add)
	ts.Gw.reloadURLStructure(add)
	ts.Gw.ReloadTestCase.TickOk(t)
	x := n.Load().(int)
	if x != 1 {
		t.Errorf("expected 1 got %d", x)
	}
}

func TestReloadLoop_handler(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()
	var n atomic.Value
	add := func() {
		if x := n.Load(); x != nil {
			n.Store(x.(int) + 1)
		} else {
			n.Store(int(1))
		}
	}
	h := ts.Gw.resetHandler(add)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/reload", nil)
	h(w, r)
	ts.Gw.ReloadTestCase.TickOk(t)
	x := n.Load().(int)
	if x != 1 {
		t.Errorf("expected 1 got %d", x)
	}
}

func TestReloadLoop_handlerWithBlock(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()

	signal := make(chan struct{}, 1)
	go func() {
		h := ts.Gw.resetHandler(nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/reload", nil)
		q := make(url.Values)
		q.Set("block", "true")
		r.URL.RawQuery = q.Encode()

		// we need to do this to make sure the goroutine has been scheduled before we
		// trigger a tick.
		signal <- struct{}{}
		h(w, r)
		signal <- struct{}{}
	}()
	<-signal
	ts.Gw.ReloadTestCase.TickOk(t)
	select {
	case <-signal:
	case <-time.After(10 * time.Millisecond):
		t.Fatal("Timedout on a blocking reload")
	}
}

func TestReloadLoop_group(t *testing.T) {
	test.Flaky(t) // TODO: TT-5252

	ts := StartTest(nil)
	defer ts.Close()

	res, err := http.Get(testReloadGroup)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected %d got %d", http.StatusOK, res.StatusCode)
	}

	ts.Gw.requeueLock.Lock()
	n := len(ts.Gw.requeue)
	ts.Gw.requeue = []func(){}
	ts.Gw.requeueLock.Unlock()
	if n != 1 {
		t.Errorf("expected 1 reload queue got %d", n)
	}
}

func TestReloadLoop_DashboardNonceRecoveryDoesNotDeadlock(t *testing.T) {
	const (
		classicAPIID = "reload-recovery-classic"
		classicPath  = "/reload-recovery-classic/"
		mcpAPIID     = "reload-recovery-mcp"
		mcpPath      = "/reload-recovery-mcp/"
		burstSize    = 3
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	classicSpec := BuildAPI(func(spec *APISpec) {
		spec.APIID = classicAPIID
		spec.Name = "Reload Recovery Classic"
		spec.Active = true
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = classicPath
		spec.Proxy.TargetURL = upstream.URL
	})[0]

	mcpSpec := BuildAPI(func(spec *APISpec) {
		spec.APIID = mcpAPIID
		spec.Name = "Reload Recovery MCP"
		spec.Active = true
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = mcpPath
		spec.Proxy.TargetURL = upstream.URL
		spec.IsOAS = true
		spec.MarkAsMCP()
		spec.OAS = oas.OAS{T: openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "Reload Recovery MCP",
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
		}}
		spec.OAS.Fill(*spec.APIDefinition)
	})[0]

	apiList := model.NewMergedAPIList(
		model.MergedAPI{APIDefinition: classicSpec.APIDefinition},
		model.MergedAPI{APIDefinition: mcpSpec.APIDefinition, OAS: &mcpSpec.OAS},
	)
	apiList.Nonce = "apis-nonce"

	var (
		apiRequests      atomic.Int32
		policyRequests   atomic.Int32
		registrations    atomic.Int32
		recoveredNonce   atomic.Value
		firstAPIRequest  = make(chan struct{})
		returnNonceError = make(chan struct{})
	)

	dashboard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/system/policies":
			policyRequests.Add(1)
			assert.NoError(t, json.NewEncoder(w).Encode(struct {
				Message []any
				Nonce   string
			}{Message: []any{}, Nonce: "policy-nonce"}))

		case "/system/apis":
			requestNumber := apiRequests.Add(1)
			if requestNumber == 1 {
				close(firstAPIRequest)
				<-returnNonceError
				w.WriteHeader(http.StatusForbidden)
				_, err := w.Write([]byte("Nonce failed"))
				assert.NoError(t, err)
				return
			}
			if requestNumber == 2 {
				recoveredNonce.Store(r.Header.Get(header.XTykNonce))
			}
			assert.NoError(t, json.NewEncoder(w).Encode(apiList))

		case "/register/node":
			registrations.Add(1)
			assert.NoError(t, json.NewEncoder(w).Encode(NodeResponse{
				Status:  "OK",
				Message: map[string]string{"NodeID": "reload-recovery-node"},
				Nonce:   "recovered-nonce",
			}))

		default:
			http.NotFound(w, r)
		}
	}))
	defer dashboard.Close()

	ts := StartTest(func(conf *config.Config) {
		conf.ResourceSync.RetryAttempts = 0
		conf.NodeSecret = "test-secret"
	})
	defer ts.Close()

	conf := ts.Gw.GetConfig()
	conf.UseDBAppConfigs = true
	conf.DisableDashboardZeroConf = true
	conf.DBAppConfOptions.ConnectionString = dashboard.URL
	conf.DBAppConfOptions.ConnectionTimeout = 2
	conf.Policies.PolicySource = config.PolicySourceService
	conf.Policies.PolicyConnectionString = dashboard.URL
	ts.Gw.SetConfig(conf)
	ts.Gw.resetDashboardClient()
	ts.Gw.DashService = &HTTPDashboardHandler{
		Gw:                   ts.Gw,
		Secret:               "test-secret",
		RegistrationEndpoint: dashboard.URL + "/register/node",
	}

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()
	ts.Gw.ReloadTestCase.Reset()

	initialReloadDone := make(chan struct{}, 1)
	burstReloadDone := make(chan struct{}, burstSize)
	ts.Gw.reloadURLStructure(func() { initialReloadDone <- struct{}{} })
	ts.Gw.ReloadTestCase.EnsureQueued(t)
	ts.Gw.ReloadTestCase.Tick()

	select {
	case <-firstAPIRequest:
	case <-time.After(5 * time.Second):
		t.Fatal("first Dashboard API sync did not start")
	}

	for range burstSize {
		ts.Gw.reloadURLStructure(func() { burstReloadDone <- struct{}{} })
	}
	require.Eventually(t, func() bool {
		ts.Gw.requeueLock.Lock()
		defer ts.Gw.requeueLock.Unlock()
		return len(ts.Gw.requeue) == burstSize
	}, 5*time.Second, time.Millisecond, "notification burst was not queued during the active reload")

	close(returnNonceError)
	select {
	case <-initialReloadDone:
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not complete after Dashboard nonce recovery")
	}

	require.Eventually(t, func() bool {
		ts.Gw.ReloadTestCase.mu.RLock()
		defer ts.Gw.ReloadTestCase.mu.RUnlock()
		return ts.Gw.ReloadTestCase.cycles >= 1
	}, 5*time.Second, time.Millisecond, "reload-loop completion callback did not run")
	require.Equal(t, int32(1), registrations.Load())
	require.Equal(t, int32(2), apiRequests.Load())
	require.Equal(t, "recovered-nonce", recoveredNonce.Load())
	require.NotZero(t, policyRequests.Load())

	classicLoaded := ts.Gw.getApiSpec(classicAPIID)
	require.NotNil(t, classicLoaded)
	mcpLoaded := ts.Gw.getApiSpec(mcpAPIID)
	require.NotNil(t, mcpLoaded)
	assert.True(t, mcpLoaded.IsMCP())

	for _, path := range []string{classicPath, mcpPath} {
		resp, err := ts.Do(test.TestCase{Method: http.MethodGet, Path: path})
		require.NoError(t, err)
		assert.NotEqual(t, http.StatusNotFound, resp.StatusCode, "route %s was not installed", path)
		require.NoError(t, resp.Body.Close())
	}

	ts.Gw.ReloadTestCase.Tick()
	for range burstSize {
		select {
		case <-burstReloadDone:
		case <-time.After(5 * time.Second):
			t.Fatal("queued reload callback did not complete")
		}
	}

	require.Eventually(t, func() bool {
		ts.Gw.ReloadTestCase.mu.RLock()
		defer ts.Gw.ReloadTestCase.mu.RUnlock()
		return ts.Gw.ReloadTestCase.cycles >= 2
	}, 5*time.Second, time.Millisecond, "notification burst reload cycle did not complete")

	ts.Gw.requeueLock.Lock()
	queued := len(ts.Gw.requeue)
	ts.Gw.requeueLock.Unlock()
	assert.Zero(t, queued, "reload callback queue did not drain")
	if assert.True(t, ts.Gw.reloadMu.TryLock(), "reload mutex remained locked after recovery") {
		ts.Gw.reloadMu.Unlock()
	}
}
