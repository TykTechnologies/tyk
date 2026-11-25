package kafka

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAckController struct {
	results []AckResult
	err     error
	tokens  []string
}

func (f *fakeAckController) Acknowledge(_ context.Context, tokens []string) ([]AckResult, error) {
	f.tokens = append([]string(nil), tokens...)
	return f.results, f.err
}

type fakeOffsetController struct {
	planRequest    ResetPlanRequest
	executeRequest ResetExecuteRequest
	plan           ResetPlan
	execution      ResetExecution
	err            error
}

type fakeStatusController struct{ limit int }

func (f *fakeStatusController) StatusSnapshot(limit int) ExternalAckStatus {
	f.limit = limit
	return ExternalAckStatus{ComponentID: "input-0", InFlight: 3}
}

func (f *fakeOffsetController) PlanReset(_ context.Context, request ResetPlanRequest) (ResetPlan, error) {
	f.planRequest = request
	return f.plan, f.err
}

func (f *fakeOffsetController) ExecuteReset(_ context.Context, request ResetExecuteRequest) (ResetExecution, error) {
	f.executeRequest = request
	return f.execution, f.err
}

func registeredControllers(t *testing.T, ack AcknowledgmentController, offsets OffsetController) (*ControllerRegistry, ControllerKey) {
	t.Helper()
	registry := NewControllerRegistry()
	key := ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input-0"}
	_, err := registry.Register(key, Controllers{Acknowledgments: ack, Offsets: offsets})
	require.NoError(t, err)
	return registry, key
}

func request(handler http.Handler, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)))
	return recorder
}

func TestControllerRegistryStatusSnapshotLifecycle(t *testing.T) {
	registry := NewControllerRegistry()
	key := ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input-0"}
	_, ok := registry.StatusSnapshot(key, 3)
	require.False(t, ok)
	status := &fakeStatusController{}
	registration, err := registry.Register(key, Controllers{Status: status})
	require.NoError(t, err)
	snapshot, ok := registry.StatusSnapshot(key, 7)
	require.True(t, ok)
	require.Equal(t, 7, status.limit)
	require.Equal(t, "input-0", snapshot.ComponentID)
	require.True(t, registration.Unregister())
	_, ok = registry.StatusSnapshot(key, 7)
	require.False(t, ok)
}

func TestAcknowledgmentHandler(t *testing.T) {
	t.Run("applied", func(t *testing.T) {
		controller := &fakeAckController{results: []AckResult{{Disposition: AckApplied}, {Disposition: AckApplied}}}
		registry, key := registeredControllers(t, controller, nil)
		response := request(NewAcknowledgmentHandler(registry, key, HandlerLimits{}), `{"tokens":["one","two"]}`)
		assert.Equal(t, http.StatusOK, response.Code)
		assert.Equal(t, []string{"one", "two"}, controller.tokens)
	})

	t.Run("mixed results", func(t *testing.T) {
		controller := &fakeAckController{results: []AckResult{{Disposition: AckApplied}, {Disposition: AckExpired}}}
		registry, key := registeredControllers(t, controller, nil)
		response := request(NewAcknowledgmentHandler(registry, key, HandlerLimits{}), `{"tokens":["one","two"]}`)
		assert.Equal(t, http.StatusMultiStatus, response.Code)
		assert.JSONEq(t, `{"results":[{"status":"applied"},{"status":"expired"}]}`, response.Body.String())
	})

	t.Run("uniform status mapping", func(t *testing.T) {
		cases := []struct {
			disposition AckDisposition
			status      int
		}{{AckQueued, 202}, {AckInvalid, 400}, {AckStale, 409}, {AckExpired, 410}, {AckUnavailable, 503}}
		for _, test := range cases {
			t.Run(string(test.disposition), func(t *testing.T) {
				controller := &fakeAckController{results: []AckResult{{Disposition: test.disposition}}}
				registry, key := registeredControllers(t, controller, nil)
				response := request(NewAcknowledgmentHandler(registry, key, HandlerLimits{}), `{"tokens":["one"]}`)
				assert.Equal(t, test.status, response.Code)
			})
		}
	})

	t.Run("applied and duplicate are both successful", func(t *testing.T) {
		controller := &fakeAckController{results: []AckResult{{Disposition: AckApplied}, {Disposition: AckDuplicate}}}
		registry, key := registeredControllers(t, controller, nil)
		response := request(NewAcknowledgmentHandler(registry, key, HandlerLimits{}), `{"tokens":["one","two"]}`)
		assert.Equal(t, http.StatusOK, response.Code)
	})

	t.Run("strict and bounded input", func(t *testing.T) {
		controller := &fakeAckController{}
		registry, key := registeredControllers(t, controller, nil)
		handler := NewAcknowledgmentHandler(registry, key, HandlerLimits{MaxRequestBytes: 40, MaxTokens: 1, MaxTokenBytes: 3})
		for name, body := range map[string]string{
			"unknown field":  `{"tokens":["one"],"offset":4}`,
			"empty":          `{"tokens":[]}`,
			"too many":       `{"tokens":["one","two"]}`,
			"token too long": `{"tokens":["four"]}`,
			"trailing value": `{"tokens":["one"]} {}`,
		} {
			t.Run(name, func(t *testing.T) {
				assert.NotEqual(t, http.StatusOK, request(handler, body).Code)
			})
		}
		assert.Equal(t, http.StatusRequestEntityTooLarge, request(handler, `{"tokens":["012345678901234567890123456789"]}`).Code)
	})

	t.Run("controller contract failure is generic", func(t *testing.T) {
		controller := &fakeAckController{err: errors.New("broker kafka.internal:9092 rejected secret")}
		registry, key := registeredControllers(t, controller, nil)
		response := request(NewAcknowledgmentHandler(registry, key, HandlerLimits{}), `{"tokens":["one"]}`)
		assert.Equal(t, http.StatusServiceUnavailable, response.Code)
		assert.NotContains(t, response.Body.String(), "kafka.internal")
	})
}

func TestControlRateLimiterRefillAndBounds(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := newControlRateLimiter(2, 2, func() time.Time { return now })
	allowed, _ := limiter.allow()
	require.True(t, allowed)
	allowed, _ = limiter.allow()
	require.True(t, allowed)
	allowed, retry := limiter.allow()
	require.False(t, allowed)
	assert.Equal(t, time.Second, retry, "Retry-After is rounded to a usable HTTP delay")
	now = now.Add(500 * time.Millisecond)
	allowed, _ = limiter.allow()
	require.True(t, allowed)

	capped := NewControlRateLimiter(1e9, 1_000_000)
	assert.Equal(t, float64(maxControlRate), capped.rate)
	assert.Equal(t, float64(maxControlBurst), capped.capacity)
	ackDefaults := NewAcknowledgmentRateLimiter(0, 0)
	assert.Equal(t, float64(defaultAckRate), ackDefaults.rate)
	assert.Equal(t, float64(defaultAckBurst), ackDefaults.capacity)
	resetDefaults := NewResetRateLimiter(0, 0)
	assert.Equal(t, float64(defaultResetRate), resetDefaults.rate)
	assert.Equal(t, float64(defaultResetBurst), resetDefaults.capacity)
}

func TestControlRateLimiterReconfigurePreservesExhaustion(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := newControlRateLimiter(1, 1, func() time.Time { return now })
	ok, _ := limiter.allow()
	require.True(t, ok)
	limiter.reconfigure(100, 100, true)
	ok, _ = limiter.allow()
	require.False(t, ok, "configuration changes must not mint a fresh burst")
	now = now.Add(10 * time.Millisecond)
	ok, _ = limiter.allow()
	require.True(t, ok, "new refill rate applies to existing state")
}

func TestControlRateLimiterConcurrentBurst(t *testing.T) {
	limiter := newControlRateLimiter(1, 25, func() time.Time { return time.Unix(100, 0) })
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _ := limiter.allow()
			if ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 25, allowed)
}

func TestControlHandlersHaveIndependentLimits(t *testing.T) {
	ack := &fakeAckController{results: []AckResult{{Disposition: AckApplied}}}
	offsets := &fakeOffsetController{plan: ResetPlan{ID: "plan"}}
	registry, key := registeredControllers(t, ack, offsets)
	ackLimiter := newControlRateLimiter(1, 1, func() time.Time { return time.Unix(100, 0) })
	resetLimiter := newControlRateLimiter(1, 1, func() time.Time { return time.Unix(100, 0) })
	ackHandler := NewAcknowledgmentHandler(registry, key, HandlerLimits{RateLimiter: ackLimiter})
	resetHandler := NewResetPlanHandler(registry, key, HandlerLimits{RateLimiter: resetLimiter})

	assert.Equal(t, http.StatusOK, request(ackHandler, `{"tokens":["one"]}`).Code)
	limited := request(ackHandler, `{"tokens":["one"]}`)
	assert.Equal(t, http.StatusTooManyRequests, limited.Code)
	assert.Equal(t, "1", limited.Header().Get("Retry-After"))
	assert.Equal(t, http.StatusOK, request(resetHandler, `{"consumer_group":"group","reason":"replay","targets":[{"topic":"topic","partition":0,"offset":1}]}`).Code)
}

func TestRegistryRateLimiterLifecycleAndClasses(t *testing.T) {
	registry, key := registeredControllers(t, &fakeAckController{}, &fakeOffsetController{})
	ack, ok := registry.RateLimiter(key, "ack", 1, 1)
	require.True(t, ok)
	ackAgain, ok := registry.RateLimiter(key, "ack", 100, 100)
	require.True(t, ok)
	assert.Same(t, ack, ackAgain)
	reset, ok := registry.RateLimiter(key, "reset-plan", 1, 1)
	require.True(t, ok)
	assert.NotSame(t, ack, reset)
	_, ok = registry.RateLimiter(key, "attacker-controlled", 1, 1)
	assert.False(t, ok)

	registry.mu.Lock()
	registration := registry.controllers[key]
	owner := registration.owner
	registry.mu.Unlock()
	require.True(t, registry.unregister(key, owner))
	_, ok = registry.RateLimiter(key, "ack", 1, 1)
	assert.False(t, ok, "unregistration removes limiter state with the component")
	_, err := registry.Register(key, Controllers{Acknowledgments: &fakeAckController{}})
	require.NoError(t, err)
	replacement, ok := registry.RateLimiter(key, "ack", 1, 1)
	require.True(t, ok)
	assert.NotSame(t, ack, replacement)
}

func TestAcknowledgmentStatusHandler(t *testing.T) {
	registry := NewControllerRegistry()
	key := ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input-0"}
	status := &fakeStatusController{}
	_, err := registry.Register(key, Controllers{Status: status})
	require.NoError(t, err)
	handler := NewAcknowledgmentStatusHandler(registry, key)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/?partition_limit=7", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, 7, status.limit)
	assert.JSONEq(t, `{"api_id":"","stream_id":"","component_id":"input-0","cluster_id_hash":"","replay_generation":"","closed":false,"in_flight":3,"in_flight_bytes":0,"pending_commits":0,"partitions":null,"truncated_partitions":0,"metrics":{"delivered":0,"capacity_rejects":0,"ack_applied":0,"ack_duplicate":0,"ack_invalid":0,"ack_stale":0,"ack_expired":0,"ack_unavailable":0,"commit_attempts":0,"commit_failures":0}}`, recorder.Body.String())

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/?partition_limit=999", nil))
	require.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestResetPlanHandler(t *testing.T) {
	offset := int64(1200)
	controller := &fakeOffsetController{plan: ResetPlan{
		ID: "plan-1", ExpiresAt: time.Unix(100, 0).UTC(),
		Targets: []ResolvedResetTarget{{Topic: "employees", Partition: 0, CurrentOffset: 1300, TargetOffset: 1200}},
	}}
	registry, key := registeredControllers(t, nil, controller)
	handler := NewResetPlanHandler(registry, key, HandlerLimits{MaxResetTargets: 2, RateLimiter: NewResetRateLimiter(100, 100)})

	valid := request(handler, `{"consumer_group":"group","reason":"replay","targets":[{"topic":"employees","partition":0,"offset":1200}]}`)
	assert.Equal(t, http.StatusOK, valid.Code)
	require.Len(t, controller.planRequest.Targets, 1)
	assert.Equal(t, offset, *controller.planRequest.Targets[0].Offset)

	invalid := []string{
		`{"consumer_group":"","reason":"replay","targets":[{"topic":"employees","partition":0,"offset":1200}]}`,
		`{"consumer_group":"group","reason":"","targets":[{"topic":"employees","partition":0,"offset":1200}]}`,
		`{"consumer_group":"group","reason":"replay","targets":[]}`,
		`{"consumer_group":"group","reason":"replay","targets":[{"topic":"employees","partition":-1,"offset":1200}]}`,
		`{"consumer_group":"group","reason":"replay","targets":[{"topic":"employees","partition":0}]}`,
		`{"consumer_group":"group","reason":"replay","targets":[{"topic":"employees","partition":0,"offset":1200,"timestamp_ms":1780000000000}]}`,
		`{"consumer_group":"group","reason":"replay","targets":[{"topic":"employees","partition":0,"offset":-1}]}`,
		`{"consumer_group":"group","reason":"replay","targets":[{"topic":"employees","partition":0,"timestamp_ms":-1}]}`,
		`{"consumer_group":"group","reason":"replay","targets":[{"topic":"employees","partition":0,"offset":1},{"topic":"employees","partition":0,"timestamp_ms":2}]}`,
		`{"consumer_group":"group","reason":"replay","targets":[{"topic":"employees","partition":0,"offset":1}],"unknown":true}`,
	}
	for _, body := range invalid {
		assert.Equal(t, http.StatusBadRequest, request(handler, body).Code, body)
	}
	assert.Equal(t, http.StatusRequestEntityTooLarge, request(handler,
		`{"consumer_group":"group","reason":"replay","targets":[{"topic":"a","partition":0,"offset":1},{"topic":"b","partition":0,"offset":1},{"topic":"c","partition":0,"offset":1}]}`).Code)
}

func TestResetExecuteHandlerAndGenericErrors(t *testing.T) {
	controller := &fakeOffsetController{execution: ResetExecution{ID: "execution-1", Status: "running"}}
	registry, key := registeredControllers(t, nil, controller)
	handler := NewResetExecuteHandler(registry, key, HandlerLimits{})

	response := request(handler, `{"plan_id":"plan-1"}`)
	assert.Equal(t, http.StatusAccepted, response.Code)
	assert.Equal(t, "plan-1", controller.executeRequest.PlanID)

	assert.Equal(t, http.StatusBadRequest, request(handler, `{"plan_id":""}`).Code)

	controller.err = &ControlError{Status: http.StatusConflict, Err: errors.New("member kafka.internal holds partition")}
	response = request(handler, `{"plan_id":"plan-1"}`)
	assert.Equal(t, http.StatusConflict, response.Code)
	assert.NotContains(t, response.Body.String(), "kafka.internal")
}

func TestControllerRegistryScopesByComponent(t *testing.T) {
	registry := NewControllerRegistry()
	first := ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "first"}
	second := ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "second"}
	firstOwner, err := registry.Register(first, Controllers{Acknowledgments: &fakeAckController{}})
	require.NoError(t, err)
	_, err = registry.Register(second, Controllers{Acknowledgments: &fakeAckController{}})
	require.NoError(t, err)
	_, err = registry.Register(first, Controllers{Acknowledgments: &fakeAckController{}})
	assert.Error(t, err)
	firstOwner.Unregister()
	_, exists := registry.lookup(first)
	assert.False(t, exists)
	_, exists = registry.lookup(second)
	assert.True(t, exists)
}

func TestControllerRegistryStaleOwnerCannotRemoveReplacement(t *testing.T) {
	registry := NewControllerRegistry()
	key := ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}
	oldController := &fakeAckController{}
	oldOwner, err := registry.Register(key, Controllers{Acknowledgments: oldController})
	require.NoError(t, err)
	require.True(t, oldOwner.Unregister())

	newController := &fakeAckController{}
	newOwner, err := registry.Register(key, Controllers{Acknowledgments: newController})
	require.NoError(t, err)
	assert.False(t, oldOwner.Unregister(), "stale teardown must not remove a replacement")
	registered, exists := registry.lookup(key)
	require.True(t, exists)
	assert.Same(t, newController, registered.Acknowledgments)
	assert.True(t, newOwner.Unregister())
	assert.False(t, newOwner.Unregister(), "release is idempotent")
}

func TestControllerRegistryConcurrentStaleTeardown(t *testing.T) {
	registry := NewControllerRegistry()
	key := ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}
	staleOwner, err := registry.Register(key, Controllers{Acknowledgments: &fakeAckController{}})
	require.NoError(t, err)
	require.True(t, staleOwner.Unregister())
	currentController := &fakeAckController{}
	currentOwner, err := registry.Register(key, Controllers{Acknowledgments: currentController})
	require.NoError(t, err)

	const workers = 32
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for range 100 {
				staleOwner.Unregister()
				registry.lookup(key)
			}
		}()
	}
	wait.Wait()
	registered, exists := registry.lookup(key)
	require.True(t, exists)
	assert.Same(t, currentController, registered.Acknowledgments)
	assert.True(t, currentOwner.Unregister())
}
