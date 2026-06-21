package gateway

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

type healthWindowCall struct {
	key      string
	per      int64
	val      string
	pipeline bool
}

type healthWindowResponse struct {
	count int
	vals  []interface{}
}

type recordingHealthStorage struct {
	*storage.DummyStorage
	mu           sync.Mutex
	connectCalls int
	calls        []healthWindowCall
	responses    map[string]healthWindowResponse
	callCh       chan healthWindowCall
}

func newRecordingHealthStorage() *recordingHealthStorage {
	return &recordingHealthStorage{
		DummyStorage: storage.NewDummyStorage(),
		responses:    make(map[string]healthWindowResponse),
		callCh:       make(chan healthWindowCall, 8),
	}
}

func (r *recordingHealthStorage) Connect() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connectCalls++
	return true
}

func (r *recordingHealthStorage) SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{}) {
	call := healthWindowCall{key: key, per: per, val: val, pipeline: pipeline}

	r.mu.Lock()
	r.calls = append(r.calls, call)
	response := r.responses[key]
	r.mu.Unlock()

	select {
	case r.callCh <- call:
	default:
	}

	return response.count, response.vals
}

func (r *recordingHealthStorage) snapshotCalls() []healthWindowCall {
	r.mu.Lock()
	defer r.mu.Unlock()

	calls := make([]healthWindowCall, len(r.calls))
	copy(calls, r.calls)
	return calls
}

func (r *recordingHealthStorage) waitForCall(t *testing.T) healthWindowCall {
	t.Helper()

	select {
	case call := <-r.callCh:
		return call
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for health storage call")
		return healthWindowCall{}
	}
}

type recordingHealthForwarder struct {
	calls []struct {
		counter HealthPrefix
		value   string
	}
}

func (r *recordingHealthForwarder) Init(storage.Handler) {}

func (r *recordingHealthForwarder) ApiHealthValues() (HealthCheckValues, error) {
	return HealthCheckValues{}, nil
}

func (r *recordingHealthForwarder) StoreCounterVal(counter HealthPrefix, value string) {
	r.calls = append(r.calls, struct {
		counter HealthPrefix
		value   string
	}{counter: counter, value: value})
}

func newHealthTestGateway(enabled bool, timeout int64) *Gateway {
	gw := &Gateway{}
	gw.SetConfig(config.Config{HealthCheck: config.HealthCheckConfig{
		EnableHealthChecks:      enabled,
		HealthCheckValueTimeout: timeout,
	}})
	return gw
}

// Verifies: STK-REQ-064, SYS-REQ-152, SW-REQ-139
// STK-REQ-064:STK-REQ-064-AC-01:acceptance
// SYS-REQ-152:nominal:nominal
// SYS-REQ-152:boundary:nominal
// SYS-REQ-152:error_handling:nominal
// SYS-REQ-152:error_handling:negative
// SYS-REQ-152:determinism:nominal
// MCDC SYS-REQ-152: gateway_api_healthcheck_helpers_operation_requested=F, gateway_api_healthcheck_helpers_operation_terminal=F => TRUE
// MCDC SYS-REQ-152: gateway_api_healthcheck_helpers_operation_requested=T, gateway_api_healthcheck_helpers_operation_terminal=T => TRUE
//
// SW-REQ-139:nominal:nominal
// SW-REQ-139:boundary:nominal
// SW-REQ-139:error_handling:nominal
// SW-REQ-139:error_handling:negative
// SW-REQ-139:determinism:nominal
// STK-REQ-064:error_handling:negative
//
//mcdc:ignore SYS-REQ-152: gateway_api_healthcheck_helpers_operation_requested=T, gateway_api_healthcheck_helpers_operation_terminal=F => FALSE -- violation row is the negation of the local health-check helper guarantee; these tests assert requested helpers initialize storage, derive keys, forward counters, invoke rolling-window storage, calculate averages, truncate values, or return aggregate health values for the tested inputs [category: defensive] [reviewed: human:buger]
func TestDefaultHealthCheckerLocalHelpers(t *testing.T) {
	t.Run("init respects health check enablement", func(t *testing.T) {
		store := newRecordingHealthStorage()
		disabled := &DefaultHealthChecker{Gw: newHealthTestGateway(false, 10), APIID: "api"}
		disabled.Init(store)
		assert.Nil(t, disabled.storage)
		assert.Equal(t, 0, store.connectCalls)

		enabled := &DefaultHealthChecker{Gw: newHealthTestGateway(true, 10), APIID: "api"}
		enabled.Init(store)
		assert.Same(t, store, enabled.storage)
		assert.Equal(t, 1, store.connectCalls)
	})

	t.Run("key naming and rounding are deterministic", func(t *testing.T) {
		checker := &DefaultHealthChecker{APIID: "api-123"}

		assert.Equal(t, "api-123.Throttle", checker.CreateKeyName(Throttle))
		assert.Equal(t, 1.23, roundValue(1.239))
		assert.Equal(t, 0.99, roundValue(0.999))
	})

	t.Run("counter forwarding follows health check enablement", func(t *testing.T) {
		health := &recordingHealthForwarder{}
		spec := &APISpec{Health: health}

		spec.GlobalConfig.HealthCheck.EnableHealthChecks = false
		reportHealthValue(spec, RequestLog, "11")
		assert.Empty(t, health.calls)

		spec.GlobalConfig.HealthCheck.EnableHealthChecks = true
		reportHealthValue(spec, RequestLog, "11")
		require.Len(t, health.calls, 1)
		assert.Equal(t, RequestLog, health.calls[0].counter)
		assert.Equal(t, "11", health.calls[0].value)
	})

	t.Run("store counter values invoke rolling window storage", func(t *testing.T) {
		store := newRecordingHealthStorage()
		checker := &DefaultHealthChecker{
			Gw:      newHealthTestGateway(true, 12),
			storage: store,
			APIID:   "api",
		}

		checker.StoreCounterVal(KeyFailure, "-1")
		call := store.waitForCall(t)
		assert.Equal(t, "api.KeyFailure", call.key)
		assert.Equal(t, int64(12), call.per)
		assert.Equal(t, "-1", call.val)
		assert.False(t, call.pipeline)

		checker.StoreCounterVal(RequestLog, "42")
		call = store.waitForCall(t)
		assert.Equal(t, "api.Request", call.key)
		assert.True(t, strings.HasSuffix(call.val, ".42"))
		assert.NotEqual(t, "42", call.val)
	})

	t.Run("average count uses configured timeout and zero-timeout fallback", func(t *testing.T) {
		store := newRecordingHealthStorage()
		store.responses["api.Throttle"] = healthWindowResponse{count: 31}
		checker := &DefaultHealthChecker{
			Gw:      newHealthTestGateway(true, 10),
			storage: store,
			APIID:   "api",
		}
		assert.Equal(t, 3.0, checker.getAvgCount(Throttle))

		store.responses["api.QuotaViolation"] = healthWindowResponse{count: 121}
		checker.Gw = newHealthTestGateway(true, 0)
		assert.Equal(t, 2.0, checker.getAvgCount(QuotaViolation))

		store.responses["api.KeyFailure"] = healthWindowResponse{}
		assert.Equal(t, 0.0, checker.getAvgCount(KeyFailure))
	})

	t.Run("api health values project counters and upstream latency", func(t *testing.T) {
		store := newRecordingHealthStorage()
		store.responses["api.Throttle"] = healthWindowResponse{count: 31}
		store.responses["api.QuotaViolation"] = healthWindowResponse{count: 16}
		store.responses["api.KeyFailure"] = healthWindowResponse{count: 1}
		store.responses["api.Request"] = healthWindowResponse{
			count: 21,
			vals:  []interface{}{"1000000.10", "1000001.20", "1000002.bad"},
		}
		checker := &DefaultHealthChecker{
			Gw:      newHealthTestGateway(true, 10),
			storage: store,
			APIID:   "api",
		}

		values, err := checker.ApiHealthValues()
		require.NoError(t, err)
		assert.Equal(t, 3.0, values.ThrottledRequestsPS)
		assert.Equal(t, 1.5, values.QuotaViolationsPS)
		assert.Equal(t, 0.0, values.KeyFailuresPS)
		assert.Equal(t, 2.0, values.AvgRequestsPS)
		assert.Equal(t, 10.0, values.AvgUpstreamLatency)

		calls := store.snapshotCalls()
		require.Len(t, calls, 5)
		for _, call := range calls {
			assert.Equal(t, int64(10), call.per)
			assert.Equal(t, "-1", call.val)
			assert.False(t, call.pipeline)
		}
	})

	t.Run("api health values return zero latency without request samples", func(t *testing.T) {
		store := newRecordingHealthStorage()
		checker := &DefaultHealthChecker{
			Gw:      newHealthTestGateway(true, 10),
			storage: store,
			APIID:   "api",
		}

		values, err := checker.ApiHealthValues()
		require.NoError(t, err)
		assert.Equal(t, HealthCheckValues{}, values)
	})
}
