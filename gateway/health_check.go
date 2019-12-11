package gateway

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
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

func setCurrentHealthCheckInfo(h []HealthCheckItem) {
	healthCheckLock.Lock()
	healthCheckInfo.Store(h)
	healthCheckLock.Unlock()
}

func getHealthCheckInfo() []HealthCheckItem {
	healthCheckLock.Lock()
	ret := healthCheckInfo.Load().([]HealthCheckItem)
	healthCheckLock.Unlock()
	return ret
}

type HealthCheckResponse struct {
	Status      HealthCheckStatus `json:"status"`
	Version     string            `json:"version,omitempty"`
	Output      string            `json:"output,omitempty"`
	Description string            `json:"description,omitempty"`
	Details     []HealthCheckItem `json:"details,omitempty"`
}

type HealthCheckItem struct {
	Status        HealthCheckStatus `json:"status"`
	Output        string            `json:"output,omitempty"`
	ComponentType string            `json:"componentType,omitempty"`
	ComponentID   string            `json:"componentId,omitempty"`
	Time          string            `json:"time"`
}

func initHealthCheck() {
	setCurrentHealthCheckInfo([]HealthCheckItem{})
}

func liveCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		doJSONWrite(w, http.StatusMethodNotAllowed, apiError(http.StatusText(http.StatusMethodNotAllowed)))
		return
	}

	// redisStore := storage.RedisCluster{KeyPrefix: "livenesscheck-"}

	// key := "tyk-liveness-probe"

	// err := redisStore.SetRawKey(key, key, 10)
	// if err != nil {
	// 	mainLog.WithField("liveness-check", true).Error(err)
	// 	doJSONWrite(w, http.StatusServiceUnavailable, apiError("Gateway is not connected to Redis. An error occurred while writing key to Redis"))
	// 	return
	// }

	// redisStore.DeleteRawKey(key)

	// if config.Global().UseDBAppConfigs {
	// 	if err = DashService.Ping(); err != nil {
	// 		doJSONWrite(w, http.StatusServiceUnavailable, apiError("Dashboard is down. Gateway cannot connect to the dashboard"))
	// 		return
	// 	}
	// }

	// if config.Global().Policies.PolicySource == "rpc" {
	// 	rpcStore := RPCStorageHandler{KeyPrefix: "livenesscheck-"}

	// 	if !rpcStore.Connect() {
	// 		doJSONWrite(w, http.StatusServiceUnavailable, apiError("RPC connection is down!!!"))
	// 		return
	// 	}
	// }

	res := HealthCheckResponse{
		Status:      Pass,
		Version:     VERSION,
		Description: "Tyk GW",
		Details:     getHealthCheckInfo(),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}
