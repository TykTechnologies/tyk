package health

import (
	"github.com/TykTechnologies/tyk/storage"
	logger "github.com/TykTechnologies/tyk/log"
)

type HealthPrefix string

type HealthChecker interface {
	Init(storage.StorageHandler)
	ApiHealthValues() (HealthCheckValues, error)
	StoreCounterVal(HealthPrefix, string)
}

var log = logger.Get()

type HealthCheckValues struct {
	ThrottledRequestsPS float64 `bson:"throttle_reqests_per_second,omitempty" json:"throttle_reqests_per_second"`
	QuotaViolationsPS   float64 `bson:"quota_violations_per_second,omitempty" json:"quota_violations_per_second"`
	KeyFailuresPS       float64 `bson:"key_failures_per_second,omitempty" json:"key_failures_per_second"`
	AvgUpstreamLatency  float64 `bson:"average_upstream_latency,omitempty" json:"average_upstream_latency"`
	AvgRequestsPS       float64 `bson:"average_requests_per_second,omitempty" json:"average_requests_per_second"`
}

type DefaultHealthChecker struct {
	storage storage.StorageHandler
	APIID   string
}

func (h *DefaultHealthChecker) Init(storeType storage.StorageHandler) {
	log.Warning("Health check API is deprecated, use instrumentation")
}

// reportHealthValue is a shortcut we can use throughout the app to push a health check value
func reportHealthValue(spec interface{}, counter HealthPrefix, value string) {
	return
}

func (h *DefaultHealthChecker)StoreCounterVal(p HealthPrefix, val string) {
	// No op
	return
}

func (h *DefaultHealthChecker) ApiHealthValues() (HealthCheckValues, error) {
	values := HealthCheckValues{}
	return values, nil
}