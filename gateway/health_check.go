package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/v3/rpc"

	"github.com/TykTechnologies/tyk/v3/config"
	"github.com/TykTechnologies/tyk/v3/headers"
	"github.com/TykTechnologies/tyk/v3/storage"
	"github.com/sirupsen/logrus"
)

type (
	HealthCheckStatus string

	HealthCheckComponentType string
)

const (
	Pass HealthCheckStatus = "pass"
	Fail                   = "fail"
	Warn                   = "warn"

	Component HealthCheckComponentType = "component"
	Datastore                          = "datastore"
	System                             = "system"
)

var (
	healthCheckInfo atomic.Value
	healthCheckLock sync.Mutex
)

func setCurrentHealthCheckInfo(h map[string]HealthCheckItem) {
	healthCheckLock.Lock()
	healthCheckInfo.Store(h)
	healthCheckLock.Unlock()
}

func getHealthCheckInfo() map[string]HealthCheckItem {
	healthCheckLock.Lock()
	ret := healthCheckInfo.Load().(map[string]HealthCheckItem)
	healthCheckLock.Unlock()
	return ret
}

type HealthCheckResponse struct {
	Status      HealthCheckStatus          `json:"status"`
	Version     string                     `json:"version,omitempty"`
	Output      string                     `json:"output,omitempty"`
	Description string                     `json:"description,omitempty"`
	Details     map[string]HealthCheckItem `json:"details,omitempty"`
}

type HealthCheckItem struct {
	Status        HealthCheckStatus `json:"status"`
	Output        string            `json:"output,omitempty"`
	ComponentType string            `json:"componentType,omitempty"`
	ComponentID   string            `json:"componentId,omitempty"`
	Time          string            `json:"time"`
}

func initHealthCheck(ctx context.Context) {
	setCurrentHealthCheckInfo(make(map[string]HealthCheckItem, 3))

	go func(ctx context.Context) {
		var n = config.Global().LivenessCheck.CheckDuration

		if n == 0 {
			n = 10
		}

		ticker := time.NewTicker(time.Second * n)

		for {
			select {
			case <-ctx.Done():

				ticker.Stop()
				mainLog.WithFields(logrus.Fields{
					"prefix": "health-check",
				}).Debug("Stopping Health checks for all components")
				return

			case <-ticker.C:
				gatherHealthChecks()
			}
		}
	}(ctx)
}

type SafeHealthCheck struct {
	info map[string]HealthCheckItem
	mux  sync.Mutex
}

func gatherHealthChecks() {
	allInfos := SafeHealthCheck{info: make(map[string]HealthCheckItem, 3)}

	redisStore := storage.RedisCluster{KeyPrefix: "livenesscheck-"}

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

	if config.Global().UseDBAppConfigs {
		wg.Add(1)

		go func() {
			defer wg.Done()

			var checkItem = HealthCheckItem{
				Status:        Pass,
				ComponentType: Datastore,
				Time:          time.Now().Format(time.RFC3339),
			}

			if DashService == nil {
				err := errors.New("Dashboard service not initialized")
				mainLog.WithField("liveness-check", true).Error(err)
				checkItem.Output = err.Error()
				checkItem.Status = Fail
			} else if err := DashService.Ping(); err != nil {
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

	if config.Global().Policies.PolicySource == "rpc" {

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
	setCurrentHealthCheckInfo(allInfos.info)
	allInfos.mux.Unlock()
}

func liveCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		doJSONWrite(w, http.StatusMethodNotAllowed, apiError(http.StatusText(http.StatusMethodNotAllowed)))
		return
	}

	checks := getHealthCheckInfo()

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

	w.Header().Set("Content-Type", headers.ApplicationJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}
