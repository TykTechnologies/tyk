package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
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

func setCurrentHealthCheckInfo(h *sync.Map) {
	healthCheckLock.Lock()
	healthCheckInfo.Store(h)
	healthCheckLock.Unlock()
}

func getHealthCheckInfo() map[string]HealthCheckItem {
	healthCheckLock.Lock()
	syncMap := healthCheckInfo.Load()
	healthCheckLock.Unlock()

	sm, ok := syncMap.(sync.Map)
	if !ok {
		log.WithField("health-check-info", syncMap).Error("could not load; stored health check info is of incorrect type")
	}

	ret := make(map[string]HealthCheckItem)

	sm.Range(func(key, value interface{}) bool {
		k, kOK := key.(string)
		v, vOK := value.(HealthCheckItem)
		if !kOK || !vOK {
			return false
		}
		ret[k] = v
		return true
	})
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
	setCurrentHealthCheckInfo(&sync.Map{})

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

func gatherHealthChecks() {
	hcInfo := &sync.Map{}
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

		hcInfo.Store("redis", checkItem)
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
			hcInfo.Store("dashboard", checkItem)
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

			rpcStore := RPCStorageHandler{KeyPrefix: "livenesscheck-"}

			if !rpcStore.Connect() {
				checkItem.Output = "Could not connect to RPC"
				checkItem.Status = Fail
			}

			checkItem.ComponentType = System
			hcInfo.Store("rpc", checkItem)
		}()
	}

	wg.Wait()

	setCurrentHealthCheckInfo(hcInfo)
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

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}
