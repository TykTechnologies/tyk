package gateway

import (
	"strconv"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/v3/config"
	"github.com/TykTechnologies/tyk/v3/storage"
)

type HealthPrefix string

const (
	Throttle          HealthPrefix = "Throttle"
	QuotaViolation    HealthPrefix = "QuotaViolation"
	KeyFailure        HealthPrefix = "KeyFailure"
	RequestLog        HealthPrefix = "Request"
	BlockedRequestLog HealthPrefix = "BlockedRequest"
)

type HealthChecker interface {
	Init(storage.Handler)
	ApiHealthValues() (HealthCheckValues, error)
	StoreCounterVal(HealthPrefix, string)
}

type HealthCheckValues struct {
	ThrottledRequestsPS float64 `bson:"throttle_reqests_per_second,omitempty" json:"throttle_reqests_per_second"`
	QuotaViolationsPS   float64 `bson:"quota_violations_per_second,omitempty" json:"quota_violations_per_second"`
	KeyFailuresPS       float64 `bson:"key_failures_per_second,omitempty" json:"key_failures_per_second"`
	AvgUpstreamLatency  float64 `bson:"average_upstream_latency,omitempty" json:"average_upstream_latency"`
	AvgRequestsPS       float64 `bson:"average_requests_per_second,omitempty" json:"average_requests_per_second"`
}

type DefaultHealthChecker struct {
	storage storage.Handler
	APIID   string
}

func (h *DefaultHealthChecker) Init(storeType storage.Handler) {
	if !config.Global().HealthCheck.EnableHealthChecks {
		return
	}

	log.Info("Initializing HealthChecker")
	h.storage = storeType
	h.storage.Connect()
}

func (h *DefaultHealthChecker) CreateKeyName(subKey HealthPrefix) string {
	// Key should be API-ID.SubKey.123456789
	return h.APIID + "." + string(subKey)
}

// reportHealthValue is a shortcut we can use throughout the app to push a health check value
func reportHealthValue(spec *APISpec, counter HealthPrefix, value string) {
	if !spec.GlobalConfig.HealthCheck.EnableHealthChecks {
		return
	}

	spec.Health.StoreCounterVal(counter, value)
}

func (h *DefaultHealthChecker) StoreCounterVal(counterType HealthPrefix, value string) {
	searchStr := h.CreateKeyName(counterType)
	log.Debug("Adding Healthcheck to: ", searchStr)
	log.Debug("Val is: ", value)
	//go h.storage.SetKey(searchStr, value, config.Global.HealthCheck.HealthCheckValueTimeout)
	if value != "-1" {
		// need to ensure uniqueness
		now_string := strconv.Itoa(int(time.Now().UnixNano()))
		value = now_string + "." + value
		log.Debug("Set value to: ", value)
	}
	go h.storage.SetRollingWindow(searchStr, config.Global().HealthCheck.HealthCheckValueTimeout, value, false)
}

func (h *DefaultHealthChecker) getAvgCount(prefix HealthPrefix) float64 {
	searchStr := h.CreateKeyName(prefix)
	log.Debug("Searching for: ", searchStr)

	count, _ := h.storage.SetRollingWindow(searchStr, config.Global().HealthCheck.HealthCheckValueTimeout, "-1", false)
	log.Debug("Count is: ", count)
	divisor := float64(config.Global().HealthCheck.HealthCheckValueTimeout)
	if divisor == 0 {
		log.Warning("The Health Check sample timeout is set to 0, samples will never be deleted!!!")
		divisor = 60.0
	}
	if count > 0 {
		return roundValue((float64(count) - 1) / divisor)
	}

	return 0.00
}

func roundValue(untruncated float64) float64 {
	return float64(int(untruncated*100)) / 100
}

func (h *DefaultHealthChecker) ApiHealthValues() (HealthCheckValues, error) {
	values := HealthCheckValues{}

	// Get the counted / average values
	values.ThrottledRequestsPS = h.getAvgCount(Throttle)
	values.QuotaViolationsPS = h.getAvgCount(QuotaViolation)
	values.KeyFailuresPS = h.getAvgCount(KeyFailure)
	values.AvgRequestsPS = h.getAvgCount(RequestLog)

	// Get the micro latency graph, an average upstream latency
	searchStr := h.APIID + "." + string(RequestLog)
	log.Debug("Searching KV for: ", searchStr)
	_, vals := h.storage.SetRollingWindow(searchStr, config.Global().HealthCheck.HealthCheckValueTimeout, "-1", false)
	log.Debug("Found: ", vals)
	if len(vals) == 0 {
		return values, nil
	}
	var runningTotal int
	for _, v := range vals {
		s := v.(string)
		log.Debug("V is: ", s)
		splitValues := strings.Split(s, ".")
		if len(splitValues) > 1 {
			vInt, err := strconv.Atoi(splitValues[1])
			if err != nil {
				log.Error("Couldn't convert tracked latency value to Int, vl is: ", err)
			} else {
				runningTotal += vInt
			}
		}

	}
	values.AvgUpstreamLatency = roundValue(float64(runningTotal / len(vals)))
	return values, nil
}
