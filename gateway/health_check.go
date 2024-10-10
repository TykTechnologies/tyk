package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

<<<<<<< HEAD
	"github.com/TykTechnologies/tyk/rpc"

=======
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/storage"
)

<<<<<<< HEAD
func (gw *Gateway) setCurrentHealthCheckInfo(h map[string]apidef.HealthCheckItem) {
	gw.healthCheckInfo.Store(h)
}

func (gw *Gateway) getHealthCheckInfo() map[string]apidef.HealthCheckItem {
	ret, ok := gw.healthCheckInfo.Load().(map[string]apidef.HealthCheckItem)
	if !ok {
		return make(map[string]apidef.HealthCheckItem, 0)
=======
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
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)
	}
	return ret
}

func (gw *Gateway) initHealthCheck(ctx context.Context) {
<<<<<<< HEAD
	gw.setCurrentHealthCheckInfo(make(map[string]apidef.HealthCheckItem, 3))
=======
	gw.setCurrentHealthCheckInfo(make(map[string]HealthCheckItem, 3))
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)

	go func(ctx context.Context) {
		var n = gw.GetConfig().LivenessCheck.CheckDuration

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
				gw.gatherHealthChecks()
			}
		}
	}(ctx)
}

type SafeHealthCheck struct {
<<<<<<< HEAD
	info map[string]apidef.HealthCheckItem
=======
	info map[string]HealthCheckItem
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)
	mux  sync.Mutex
}

func (gw *Gateway) gatherHealthChecks() {
<<<<<<< HEAD
	allInfos := SafeHealthCheck{info: make(map[string]apidef.HealthCheckItem, 3)}
=======
	allInfos := SafeHealthCheck{info: make(map[string]HealthCheckItem, 3)}
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)

	redisStore := storage.RedisCluster{KeyPrefix: "livenesscheck-", ConnectionHandler: gw.StorageConnectionHandler}

	key := "tyk-liveness-probe"

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

<<<<<<< HEAD
		var checkItem = apidef.HealthCheckItem{
			Status:        apidef.Pass,
			ComponentType: apidef.Datastore,
=======
		var checkItem = HealthCheckItem{
			Status:        Pass,
			ComponentType: Datastore,
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)
			Time:          time.Now().Format(time.RFC3339),
		}

		err := redisStore.SetRawKey(key, key, 10)
		if err != nil {
			mainLog.WithField("liveness-check", true).WithError(err).Error("Redis health check failed")
			checkItem.Output = err.Error()
<<<<<<< HEAD
			checkItem.Status = apidef.Fail
=======
			checkItem.Status = Fail
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)
		}

		allInfos.mux.Lock()
		allInfos.info["redis"] = checkItem
		allInfos.mux.Unlock()
	}()

	if gw.GetConfig().UseDBAppConfigs {
		wg.Add(1)

		go func() {
			defer wg.Done()

<<<<<<< HEAD
			var checkItem = apidef.HealthCheckItem{
				Status:        apidef.Pass,
				ComponentType: apidef.Datastore,
=======
			var checkItem = HealthCheckItem{
				Status:        Pass,
				ComponentType: Datastore,
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)
				Time:          time.Now().Format(time.RFC3339),
			}

			if gw.DashService == nil {
				err := errors.New("Dashboard service not initialized")
				mainLog.WithField("liveness-check", true).Error(err)
				checkItem.Output = err.Error()
<<<<<<< HEAD
				checkItem.Status = apidef.Fail
			} else if err := gw.DashService.Ping(); err != nil {
				mainLog.WithField("liveness-check", true).Error(err)
				checkItem.Output = err.Error()
				checkItem.Status = apidef.Fail
			}

			checkItem.ComponentType = apidef.System
=======
				checkItem.Status = Fail
			} else if err := gw.DashService.Ping(); err != nil {
				mainLog.WithField("liveness-check", true).Error(err)
				checkItem.Output = err.Error()
				checkItem.Status = Fail
			}

			checkItem.ComponentType = System
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)

			allInfos.mux.Lock()
			allInfos.info["dashboard"] = checkItem
			allInfos.mux.Unlock()
		}()
	}

	if gw.GetConfig().Policies.PolicySource == "rpc" {

		wg.Add(1)

		go func() {
			defer wg.Done()

<<<<<<< HEAD
			var checkItem = apidef.HealthCheckItem{
				Status:        apidef.Pass,
				ComponentType: apidef.Datastore,
=======
			var checkItem = HealthCheckItem{
				Status:        Pass,
				ComponentType: Datastore,
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)
				Time:          time.Now().Format(time.RFC3339),
			}

			if !rpc.Login() {
				checkItem.Output = "Could not connect to RPC"
<<<<<<< HEAD
				checkItem.Status = apidef.Fail
			}

			checkItem.ComponentType = apidef.System
=======
				checkItem.Status = Fail
			}

			checkItem.ComponentType = System
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)

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

<<<<<<< HEAD
	res := apidef.HealthCheckResponse{
		Status:      apidef.Pass,
=======
	res := HealthCheckResponse{
		Status:      Pass,
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)
		Version:     VERSION,
		Description: "Tyk GW",
		Details:     checks,
	}

	var failCount int

	for _, v := range checks {
<<<<<<< HEAD
		if v.Status == apidef.Fail {
=======
		if v.Status == Fail {
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)
			failCount++
		}
	}

<<<<<<< HEAD
	var status apidef.HealthCheckStatus

	switch failCount {
	case 0:
		status = apidef.Pass

	case len(checks):
		status = apidef.Fail

	default:
		status = apidef.Warn
=======
	var status HealthCheckStatus

	switch failCount {
	case 0:
		status = Pass

	case len(checks):
		status = Fail

	default:
		status = Warn
>>>>>>> e31a08f08... [TT-12897] Merge path based permissions when combining policies (#6597)
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
