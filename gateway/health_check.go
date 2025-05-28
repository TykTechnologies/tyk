package gateway

import (
	"context"
	"encoding/json"
	"errors"
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

func (gw *Gateway) initHealthCheck(ctx context.Context) {
	gw.setCurrentHealthCheckInfo(make(map[string]HealthCheckItem, 3))

	go func(ctx context.Context) {
		var n = gw.GetConfig().LivenessCheck.CheckDuration
		if n == 0 {
			n = 10 * time.Second
		}

		ticker := time.NewTicker(n)

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

		wg.Add(1)

		go func() {
			defer wg.Done()

			var checkItem = HealthCheckItem{
				Status:        Pass,
				ComponentType: Datastore,
				Time:          time.Now().Format(time.RFC3339),
			}

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

	wg.Wait()

	allInfos.mux.Lock()
	gw.setCurrentHealthCheckInfo(allInfos.info)
	allInfos.mux.Unlock()
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

	failCount, criticalFailure := gw.evaluateHealthChecks(checks)

	status, httpStatus := gw.determineHealthStatus(failCount, criticalFailure, len(checks))

	res.Status = status

	w.Header().Set("Content-Type", header.ApplicationJSON)

	// If this option is not set, or is explicitly set to false, add the mascot headers
	if !gw.GetConfig().HideGeneratorHeader {
		addMascotHeaders(w)
	}

	w.WriteHeader(httpStatus)
	err := json.NewEncoder(w).Encode(res)
	if err != nil {
		mainLog.Warning("[Liveness] Could not encode response")
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

	// Check API definitions loaded
	gw.apisMu.RLock()
	apisLoaded := len(gw.apiSpecs) > 0
	gw.apisMu.RUnlock()

	if !apisLoaded && gw.GetConfig().UseDBAppConfigs {
		mainLog.Warning("[Readiness] No API definitions loaded")
		doJSONWrite(w, http.StatusServiceUnavailable, apiError("API definitions not loaded"))
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
	json.NewEncoder(w).Encode(res)
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

			if gw.isCriticalFailure(component, check) {
				criticalFailure = true
			}
		}
	}
	return failCount, criticalFailure
}

func (gw *Gateway) isCriticalFailure(component string, check HealthCheckItem) bool {
	// Redis is always considered critical
	if component == "redis" {
		return true
	}

	// Consider dashboard critical only if UseDBAppConfigs is enabled
	if component == "dashboard" && gw.GetConfig().UseDBAppConfigs {
		return true
	}

	// Consider RPC critical only if using RPC
	if component == "rpc" && gw.GetConfig().Policies.PolicySource == "rpc" {
		return true
	}

	return false
}
