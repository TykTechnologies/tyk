package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/storage"
)

type (
	HealthCheckItem     = model.HealthCheckItem
	HealthCheckStatus   = model.HealthCheckStatus
	HealthCheckResponse = model.HealthCheckResponse
)

const (
	Pass      = model.Pass
	Fail      = model.Fail
	Warn      = model.Warn
	Datastore = model.Datastore
	System    = model.System
)

func (gw *Gateway) setCurrentHealthCheckInfo(h map[string]model.HealthCheckItem) {
	gw.healthCheckInfo.Store(h)
}

func (gw *Gateway) getHealthCheckInfo() map[string]HealthCheckItem {
	ret, ok := gw.healthCheckInfo.Load().(map[string]HealthCheckItem)
	if !ok {
		return make(map[string]HealthCheckItem, 0)
	}
	return ret
}

// defaultHealthCheckInterval applies when liveness_check.check_duration is
// not configured.
const defaultHealthCheckInterval = 10 * time.Second

// healthCheckInterval is how often the health of all components is gathered,
// and the longest a single gather round is allowed to take.
func (gw *Gateway) healthCheckInterval() time.Duration {
	if n := gw.GetConfig().LivenessCheck.CheckDuration; n > 0 {
		return n
	}
	return defaultHealthCheckInterval
}

func (gw *Gateway) initHealthCheck(ctx context.Context) {
	gw.setCurrentHealthCheckInfo(make(map[string]HealthCheckItem, 3))

	go func(ctx context.Context) {
		ticker := time.NewTicker(gw.healthCheckInterval())

		for {
			select {
			case <-ctx.Done():

				ticker.Stop()
				mainLog.WithFields(logrus.Fields{
					"prefix": "health-check",
				}).Debug("Stopping Health checks for all components")
				return

			case <-ticker.C:
				gw.gatherHealthChecks()
			}
		}
	}(ctx)
}

type SafeHealthCheck struct {
	info map[string]HealthCheckItem
	mux  sync.Mutex
}

func (gw *Gateway) gatherHealthChecks() {
	allInfos := SafeHealthCheck{info: make(map[string]HealthCheckItem, 3)}

	// expected tracks the components probed this round, so the ones whose
	// probe does not finish in time can be reported as failed.
	expected := map[string]string{"redis": Datastore}

	redisStore := storage.RedisCluster{KeyPrefix: "livenesscheck-", ConnectionHandler: gw.StorageConnectionHandler}
	redisStore.Connect()

	key := "tyk-liveness-probe"

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		var checkItem = HealthCheckItem{
			Status:        Pass,
			ComponentType: Datastore,
			Time:          time.Now().Format(time.RFC3339),
		}

		err := redisStore.SetRawKey(key, key, 10)
		if err != nil {
			mainLog.WithField("liveness-check", true).WithError(err).Error("Redis health check failed")
			checkItem.Output = err.Error()
			checkItem.Status = Fail
		}

		allInfos.mux.Lock()
		allInfos.info["redis"] = checkItem
		allInfos.mux.Unlock()
	}()

	if gw.GetConfig().UseDBAppConfigs {
		expected["dashboard"] = System
		wg.Add(1)

		go func() {
			defer wg.Done()

			var checkItem = HealthCheckItem{
				Status:        Pass,
				ComponentType: Datastore,
				Time:          time.Now().Format(time.RFC3339),
			}

			if gw.DashService == nil {
				err := errors.New("Dashboard service not initialized")
				mainLog.WithField("liveness-check", true).Error(err)
				checkItem.Output = err.Error()
				checkItem.Status = Fail
			} else if err := gw.DashService.Ping(); err != nil {
				mainLog.WithField("liveness-check", true).Error(err)
				checkItem.Output = err.Error()
				checkItem.Status = Fail
			}

			checkItem.ComponentType = System

			allInfos.mux.Lock()
			allInfos.info["dashboard"] = checkItem
			allInfos.mux.Unlock()
		}()
	}

	if gw.GetConfig().Policies.PolicySource == "rpc" {
		expected["rpc"] = System
		wg.Add(1)

		go func() {
			defer wg.Done()

			var checkItem = HealthCheckItem{
				Status:        Pass,
				ComponentType: Datastore,
				Time:          time.Now().Format(time.RFC3339),
			}

			// rpc.Login takes no context but is internally bounded (30s call
			// timeout, max 3 retries) and singleflighted, so a slow RPC server
			// parks this goroutine for minutes at most while the bounded
			// barrier below keeps the health-check round moving.
			if !rpc.Login() {
				checkItem.Output = "Could not connect to RPC"
				checkItem.Status = Fail
			}

			checkItem.ComponentType = System

			allInfos.mux.Lock()
			allInfos.info["rpc"] = checkItem
			allInfos.mux.Unlock()
		}()
	}

	// A single hung probe must not wedge the health-check loop (TT-17486):
	// wait for the barrier only up to the check interval, then commit
	// whatever completed and mark the missing components as failed.
	barrier := make(chan struct{})
	go func() {
		wg.Wait()
		close(barrier)
	}()

	timer := time.NewTimer(gw.healthCheckInterval())
	defer timer.Stop()

	select {
	case <-barrier:
	case <-timer.C:
		mainLog.WithField("liveness-check", true).Warning("Health check timed out waiting for components")
	}

	// Copy under the mutex: a probe that finishes late may still write to
	// allInfos.info, which must not race with readers of the stored map.
	allInfos.mux.Lock()
	info := make(map[string]HealthCheckItem, len(expected))
	for component, item := range allInfos.info {
		info[component] = item
	}
	allInfos.mux.Unlock()

	for component, componentType := range expected {
		if _, ok := info[component]; !ok {
			info[component] = HealthCheckItem{
				Status:        Fail,
				Output:        "health check timed out",
				ComponentType: componentType,
				Time:          time.Now().Format(time.RFC3339),
			}
		}
	}

	gw.setCurrentHealthCheckInfo(info)
}

func (gw *Gateway) liveCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		doJSONWrite(w, http.StatusMethodNotAllowed, apiError(http.StatusText(http.StatusMethodNotAllowed)))
		return
	}

	checks := gw.getHealthCheckInfo()

	res := HealthCheckResponse{
		Status:      Pass,
		Version:     VERSION,
		Description: "Tyk GW",
		Details:     checks,
	}

	var failCount int

	for _, v := range checks {
		if v.Status == Fail {
			failCount++
		}
	}

	var status HealthCheckStatus

	switch failCount {
	case 0:
		status = Pass

	case len(checks):
		status = Fail

	default:
		status = Warn
	}

	res.Status = status

	w.Header().Set("Content-Type", header.ApplicationJSON)

	// If this option is not set, or is explicitly set to false, add the mascot headers
	if !gw.GetConfig().HideGeneratorHeader {
		addMascotHeaders(w)
	}

	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(res)
	if err != nil {
		mainLog.Warning(fmt.Sprintf("[Liveness] Could not encode response, error: %s", err.Error()))
	}
}

// readinessHandler is a dedicated endpoint for readiness probes
// It checks if the gateway is ready to serve requests by verifying:
// - Redis connection status
// - API definitions loaded successfully
// Unlike liveCheckHandler which always returns 200 OK, readinessHandler returns 503 Service Unavailable
// if the gateway is not ready to serve requests
func (gw *Gateway) readinessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		doJSONWrite(w, http.StatusMethodNotAllowed, apiError(http.StatusText(http.StatusMethodNotAllowed)))
		return
	}

	if gw.shuttingDown.Load() {
		doJSONWrite(w, http.StatusServiceUnavailable, apiError("Gateway is shutting down"))
		return
	}

	// Reuse existing health check data
	checks := gw.getHealthCheckInfo()

	// Check Redis connection specifically
	if redisCheck, exists := checks["redis"]; exists {
		if redisCheck.Status == Fail {
			mainLog.Warning("[Readiness] Redis health check failed")
			doJSONWrite(w, http.StatusServiceUnavailable, apiError("Redis connection not available"))
			return
		}
	} else {
		// If Redis check doesn't exist in health checks, check connection directly
		if !gw.StorageConnectionHandler.Connected() {
			mainLog.Warning("[Readiness] Redis not connected")
			doJSONWrite(w, http.StatusServiceUnavailable, apiError("Redis connection not available"))
			return
		}
	}

	if !gw.performedSuccessfulReload {
		mainLog.Warning("[Readiness] Successful reload check failed")
		doJSONWrite(w, http.StatusServiceUnavailable, apiError("A successful API reload did not happen"))
		return
	}

	// All checks passed - use similar response format as liveCheckHandler
	res := HealthCheckResponse{
		Status:      Pass,
		Version:     VERSION,
		Description: "Tyk GW Ready",
		Details:     checks,
	}

	w.Header().Set("Content-Type", header.ApplicationJSON)

	if !gw.GetConfig().HideGeneratorHeader {
		addMascotHeaders(w)
	}

	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(res)
	if err != nil {
		mainLog.Warning(fmt.Sprintf("[Readiness] Could not encode response, error: %s", err.Error()))
	}
}

func (gw *Gateway) determineHealthStatus(failCount int, criticalFailure bool, totalChecks int) (HealthCheckStatus, int) {
	switch {
	case failCount == 0:
		return Pass, http.StatusOK
	case criticalFailure:
		return Fail, http.StatusServiceUnavailable
	case failCount == totalChecks:
		return Fail, http.StatusServiceUnavailable
	default:
		// Non-critical failures return a warning but still 200 OK
		return Warn, http.StatusOK
	}
}

func (gw *Gateway) evaluateHealthChecks(checks map[string]HealthCheckItem) (failCount int, criticalFailure bool) {
	// Check for critical failures
	for component, check := range checks {
		if check.Status == Fail {
			failCount++

			if gw.isCriticalFailure(component) {
				criticalFailure = true
			}
		}
	}
	return failCount, criticalFailure
}

func (gw *Gateway) isCriticalFailure(component string) bool {
	// Redis is always considered critical
	if component == "redis" {
		return true
	}

	// Consider dashboard critical only if UseDBAppConfigs is enabled
	if component == "dashboard" && gw.GetConfig().UseDBAppConfigs {
		return true
	}

	// Consider RPC critical only if using RPC and gw not in emergency mode
	if component == "rpc" && gw.GetConfig().Policies.PolicySource == "rpc" && !rpc.IsEmergencyMode() {
		return true
	}

	return false
}
