package main

import (
	"strings"
	"time"
	"strconv"
)

type HealthPrefix string

const (
	Throttle HealthPrefix = "Throttle"
	QuotaViolation HealthPrefix = "QuotaViolation"
	KeyFailure HealthPrefix = "KeyFailure"
	UpstreamLatency HealthPrefix = "UpstreamLatency"
	RequestLog HealthPrefix = "Request"

	SampleTimeout int64 = 20
)

type HealthChecker interface {
	Init(StorageHandler)
	GetApiHealthValues() (HealthCheckValues, error)
	StoreCounterVal(HealthPrefix, string)
}

type HealthCheckValues struct {
	ThrottledRequestsPS int64	`bson:"throttle_reqests_per_second,omitempty" json:"throttle_reqests_per_second"`
	QuotaViolationsPS int64 `bson:"quota_violations_per_second,omitempty" json:"quota_violations_per_second"`
	KeyFailuresPS int64 `bson:"key_failures_per_second,omitempty" json:"key_failures_per_second"`
	AvgUpstreamLatency int64 `bson:"average_upstream_latency,omitempty" json:"average_upstream_latency"`
	AvgRequestsPS int64 `bson:"average_requests_per_second,omitempty" json:"average_requests_per_second"`
}

type DefaultHealthChecker struct {
	storage StorageHandler
	APIID string
}

func (h *DefaultHealthChecker) Init(storeType StorageHandler) {
	log.Info("Health Checker initialised.")
	h.storage = storeType
	h.storage.Connect()
}

func (h *DefaultHealthChecker) CreateKeyName(subKey HealthPrefix) string {
	var newKey string
	now := time.Now().UnixNano()

	// Key should be API-ID.SubKey.123456789
	newKey = strings.Join([]string{h.APIID, string(subKey), string(now)}, ".")

	return newKey
}

func (h *DefaultHealthChecker) StoreCounterVal(counterType HealthPrefix, value string) {
	h.storage.SetKey(h.CreateKeyName(counterType), value, SampleTimeout)
}

func (h *DefaultHealthChecker) getAvgCount(prefix HealthPrefix) int64 {
	keys := h.storage.GetKeys(strings.Join([]string{h.APIID, string(prefix)}, "."))
	var count int64
	count = int64(len(keys))
	if count > 0 {
		return count / SampleTimeout
	}

	return 0
}

func (h *DefaultHealthChecker) GetApiHealthValues() (HealthCheckValues, error) {
	values := HealthCheckValues{}

	// Get the counted / average values
	values.ThrottledRequestsPS = h.getAvgCount(Throttle)
	values.QuotaViolationsPS = h.getAvgCount(QuotaViolation)
	values.KeyFailuresPS = h.getAvgCount(KeyFailure)
	values.AvgRequestsPS = h.getAvgCount(RequestLog)

	// Get the micro latency graph, an average upstream latency
	kv := h.storage.GetKeysAndValuesWithFilter(strings.Join([]string{h.APIID, string(UpstreamLatency)}, "."))
	var runningTotal int
	if len(kv) > 0 {
		for _, v := range kv {
			vInt, cErr := strconv.Atoi(v)
			if cErr != nil {
				log.Error("Couldn't convert tracked latency value to Int, vl is: ")
			} else {
				runningTotal += vInt
			}
		}
		values.AvgUpstreamLatency = int64(runningTotal / len(kv))
	}

	return values, nil
}



