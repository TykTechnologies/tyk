package gateway

// TT-17486 regression test: when Redis is down but the Dashboard is up, the
// Dashboard answers the gateway heartbeat with 403 (it cannot read the
// session->node mapping from Redis) and answers registration with
// 409 + Status "Error" (its Redis-backed lock/session calls fail).
//
// The liveness probe (gatherHealthChecks -> DashService.Ping) must not block
// on, nor trigger, node re-registration in that state: Register() retries a
// 409/Status!="OK" response every 5s until its context is cancelled, so a
// probe that reaches it wedges the health-check loop and /hello and /ready
// serve a stale "pass" cache. Re-registration is owned by the heartbeat loop
// (StartBeating), not by the probe.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

// blockingPingDashService is a DashboardServiceSender whose Ping blocks until
// unblock is closed — a stand-in for any probe that hangs.
type blockingPingDashService struct {
	unblock chan struct{}
}

func (s *blockingPingDashService) Init() error                          { return nil }
func (s *blockingPingDashService) Register(_ context.Context) error     { return nil }
func (s *blockingPingDashService) DeRegister() error                    { return nil }
func (s *blockingPingDashService) StartBeating(_ context.Context) error { return nil }
func (s *blockingPingDashService) StopBeating()                         {}
func (s *blockingPingDashService) NotifyDashboardOfEvent(interface{}) error {
	return nil
}
func (s *blockingPingDashService) Ping() error {
	<-s.unblock
	return nil
}

// TestGatherHealthChecks_HungProbeDoesNotWedgeTheLoop verifies that no single
// hung dependency probe can block the health-check barrier: the round must
// complete within the check interval, commit the healthy components, and
// report the hung one as failed.
func TestGatherHealthChecks_HungProbeDoesNotWedgeTheLoop(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	unblock := make(chan struct{})
	defer close(unblock)
	ts.Gw.DashService = &blockingPingDashService{unblock: unblock}

	cfg := ts.Gw.GetConfig()
	cfg.UseDBAppConfigs = true
	cfg.LivenessCheck.CheckDuration = time.Second
	ts.Gw.SetConfig(cfg)

	done := make(chan struct{})
	go func() {
		ts.Gw.gatherHealthChecks()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("gatherHealthChecks wedged by a hung dashboard probe — /hello and /ready would serve a stale status forever")
	}

	checks := ts.Gw.getHealthCheckInfo()
	require.Contains(t, checks, "redis")
	assert.Equal(t, Pass, checks["redis"].Status)
	require.Contains(t, checks, "dashboard")
	assert.Equal(t, HealthCheckStatus(Fail), checks["dashboard"].Status)
	assert.Equal(t, "health check timed out", checks["dashboard"].Output)
}

// TestPing_HangingDashboard_BoundedByTimeout verifies the probe is bounded:
// a dashboard that accepts the connection but never answers must be reported
// as failing within the probe timeout, not block the health-check loop.
func TestPing_HangingDashboard_BoundedByTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		done <- h.Gw.DashService.Ping()
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dashboard is down? Heartbeat is failing")
	case <-time.After(7 * time.Second):
		t.Fatal("Ping() not bounded: still blocked after 7s on an unresponsive dashboard")
	}
}

func TestPing_RedisDownDashboardUp_DoesNotBlockOrReRegister(t *testing.T) {
	var registerAttempts int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/register/ping":
			// Dashboard with Redis down: GetNodeFromSessionWithFallback fails.
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"Status":"Error","Message":"Authorization failed (Session not found)"}`))
		case "/register/node":
			atomic.AddInt32(&registerAttempts, 1)
			// Dashboard with Redis down: NodeIDConn.Lock fails.
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"Status":"Error","Message":"Another registration operation in progress"}`))
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
