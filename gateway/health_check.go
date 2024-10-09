package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/rpc"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/storage"
)

func (gw *Gateway) setCurrentHealthCheckInfo(h map[string]model.HealthCheckItem) {
	gw.healthCheckInfo.Store(h)
}

func (gw *Gateway) getHealthCheckInfo() map[string]model.HealthCheckItem {
	ret, ok := gw.healthCheckInfo.Load().(map[string]model.HealthCheckItem)
	if !ok {
		return make(map[string]model.HealthCheckItem, 0)
	}
	return ret
}

func (gw *Gateway) initHealthCheck(ctx context.Context) {
	gw.setCurrentHealthCheckInfo(make(map[string]model.HealthCheckItem, 3))

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
	info map[string]model.HealthCheckItem
	mux  sync.Mutex
}

func (gw *Gateway) gatherHealthChecks() {
	allInfos := SafeHealthCheck{info: make(map[string]model.HealthCheckItem, 3)}

	redisStore := storage.RedisCluster{KeyPrefix: "livenesscheck-", ConnectionHandler: gw.StorageConnectionHandler}

	key := "tyk-liveness-probe"

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		var checkItem = model.HealthCheckItem{
			Status:        model.Pass,
			ComponentType: model.Datastore,
			Time:          time.Now().Format(time.RFC3339),
		}

		err := redisStore.SetRawKey(key, key, 10)
		if err != nil {
			mainLog.WithField("liveness-check", true).WithError(err).Error("Redis health check failed")
			checkItem.Output = err.Error()
			checkItem.Status = model.Fail
		}

		allInfos.mux.Lock()
		allInfos.info["redis"] = checkItem
		allInfos.mux.Unlock()
	}()

	if gw.GetConfig().UseDBAppConfigs {
		wg.Add(1)

		go func() {
			defer wg.Done()

			var checkItem = model.HealthCheckItem{
				Status:        model.Pass,
				ComponentType: model.Datastore,
				Time:          time.Now().Format(time.RFC3339),
			}

			if gw.DashService == nil {
				err := errors.New("Dashboard service not initialized")
				mainLog.WithField("liveness-check", true).Error(err)
				checkItem.Output = err.Error()
				checkItem.Status = model.Fail
			} else if err := gw.DashService.Ping(); err != nil {
				mainLog.WithField("liveness-check", true).Error(err)
				checkItem.Output = err.Error()
				checkItem.Status = model.Fail
			}

			checkItem.ComponentType = model.System

			allInfos.mux.Lock()
			allInfos.info["dashboard"] = checkItem
			allInfos.mux.Unlock()
		}()
	}

	if gw.GetConfig().Policies.PolicySource == "rpc" {

		wg.Add(1)

		go func() {
			defer wg.Done()

			var checkItem = model.HealthCheckItem{
				Status:        model.Pass,
				ComponentType: model.Datastore,
				Time:          time.Now().Format(time.RFC3339),
			}

			if !rpc.Login() {
				checkItem.Output = "Could not connect to RPC"
				checkItem.Status = model.Fail
			}

			checkItem.ComponentType = model.System

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

	res := model.HealthCheckResponse{
		Status:      model.Pass,
		Version:     VERSION,
		Description: "Tyk GW",
		Details:     checks,
	}

	var failCount int

	for _, v := range checks {
		if v.Status == model.Fail {
			failCount++
		}
	}

	var status model.HealthCheckStatus

	switch failCount {
	case 0:
		status = model.Pass

	case len(checks):
		status = model.Fail

	default:
		status = model.Warn
	}

	res.Status = status

	w.Header().Set("Content-Type", header.ApplicationJSON)

	// If this option is not set, or is explicitly set to false, add the mascot headers
	if !gw.GetConfig().HideGeneratorHeader {
		addMascotHeaders(w)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}
