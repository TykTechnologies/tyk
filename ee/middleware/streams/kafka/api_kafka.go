package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxRequestBytes = int64(256 * 1024)
	defaultMaxTokens       = 256
	defaultMaxTokenBytes   = 8 * 1024
	defaultMaxResetTargets = 256
	defaultAckRate         = 100
	defaultAckBurst        = 200
	defaultResetRate       = 1
	defaultResetBurst      = 5
	maxControlRate         = 10_000
	maxControlBurst        = 10_000
)

// ControlRateLimiter is a concurrency-safe, bounded token bucket used by one
// API/stream/component control class. Keeping it on the handler avoids a
// caller-controlled key map and lets removing the handler reclaim its state.
type ControlRateLimiter struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
	now      func() time.Time
}

// NewControlRateLimiter constructs a limiter with requests-per-second and
// burst bounds. Invalid values fall back to safe, non-zero values.
func NewControlRateLimiter(requestsPerSecond float64, burst int) *ControlRateLimiter {
	return newControlRateLimiter(requestsPerSecond, burst, time.Now)
}

// NewAcknowledgmentRateLimiter applies acknowledgment-specific defaults.
func NewAcknowledgmentRateLimiter(requestsPerSecond float64, burst int) *ControlRateLimiter {
	if requestsPerSecond <= 0 {
		requestsPerSecond = defaultAckRate
	}
	if burst <= 0 {
		burst = defaultAckBurst
	}
	return NewControlRateLimiter(requestsPerSecond, burst)
}

// NewResetRateLimiter applies the lower-volume reset-specific defaults.
func NewResetRateLimiter(requestsPerSecond float64, burst int) *ControlRateLimiter {
	return NewControlRateLimiter(requestsPerSecond, burst)
}

func newControlRateLimiter(requestsPerSecond float64, burst int, now func() time.Time) *ControlRateLimiter {
	if requestsPerSecond <= 0 {
		requestsPerSecond = defaultResetRate
	} else if requestsPerSecond > maxControlRate {
		requestsPerSecond = maxControlRate
	}
	if burst <= 0 {
		burst = defaultResetBurst
	} else if burst > maxControlBurst {
		burst = maxControlBurst
	}
	return &ControlRateLimiter{rate: requestsPerSecond, capacity: float64(burst), tokens: float64(burst), now: now}
}

func (l *ControlRateLimiter) allow() (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.refillLocked(now)
	if l.tokens >= 1 {
		l.tokens--
		return true, 0
	}
	wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

func (l *ControlRateLimiter) refillLocked(now time.Time) {
	if l.last.IsZero() {
		l.last = now
	} else if elapsed := now.Sub(l.last); elapsed > 0 {
		l.tokens = min(l.capacity, l.tokens+elapsed.Seconds()*l.rate)
		l.last = now
	}
}

func (l *ControlRateLimiter) reconfigure(requestsPerSecond float64, burst int, acknowledgment bool) {
	configured := NewResetRateLimiter(requestsPerSecond, burst)
	if acknowledgment {
		configured = NewAcknowledgmentRateLimiter(requestsPerSecond, burst)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillLocked(l.now())
	l.rate = configured.rate
	l.capacity = configured.capacity
	l.tokens = min(l.tokens, l.capacity)
}

// ControllerKey uniquely identifies a Kafka input within a stream. ComponentID
// is required because a stream can contain more than one Kafka input.
type ControllerKey struct {
	APIID       string
	StreamID    string
	ComponentID string
}

func (k ControllerKey) validate() error {
	if strings.TrimSpace(k.APIID) == "" || strings.TrimSpace(k.StreamID) == "" || strings.TrimSpace(k.ComponentID) == "" {
		return errors.New("api, stream, and component identifiers are required")
	}
	return nil
}

// AckDisposition describes the result for one opaque acknowledgment token.
type AckDisposition string

const (
	AckApplied     AckDisposition = "applied"
	AckDuplicate   AckDisposition = "duplicate"
	AckQueued      AckDisposition = "queued"
	AckInvalid     AckDisposition = "invalid"
	AckStale       AckDisposition = "stale"
	AckExpired     AckDisposition = "expired"
	AckUnavailable AckDisposition = "unavailable"
)

type AckResult struct {
	Disposition AckDisposition `json:"status"`
}

// AcknowledgmentController is implemented by the active connector. Results
// must correspond one-for-one and in order with the supplied tokens.
type AcknowledgmentController interface {
	Acknowledge(context.Context, []string) ([]AckResult, error)
}

type ResetTarget struct {
	Topic       string `json:"topic"`
	Partition   int32  `json:"partition"`
	Offset      *int64 `json:"offset,omitempty"`
	TimestampMS *int64 `json:"timestamp_ms,omitempty"`
}

type ResetPlanRequest struct {
	ConsumerGroup string        `json:"consumer_group"`
	Targets       []ResetTarget `json:"targets"`
	Reason        string        `json:"reason"`
}

type ResolvedResetTarget struct {
	Topic         string `json:"topic"`
	Partition     int32  `json:"partition"`
	CurrentOffset int64  `json:"current_offset"`
	TargetOffset  int64  `json:"target_offset"`
}

type ResetPlan struct {
	ID        string                `json:"plan_id"`
	ExpiresAt time.Time             `json:"expires_at"`
	Targets   []ResolvedResetTarget `json:"targets"`
}

type ResetExecuteRequest struct {
	PlanID string `json:"plan_id"`
}

type ResetExecution struct {
	ID     string `json:"execution_id,omitempty"`
	Status string `json:"status"`
}

// OffsetController is a privileged control-plane abstraction. Implementations
// own quiescence, fencing, Kafka administration, verification, and auditing.
type OffsetController interface {
	PlanReset(context.Context, ResetPlanRequest) (ResetPlan, error)
	ExecuteReset(context.Context, ResetExecuteRequest) (ResetExecution, error)
}

type Controllers struct {
	Acknowledgments AcknowledgmentController
	Offsets         OffsetController
	Status          interface{ StatusSnapshot(int) ExternalAckStatus }
}

func NewAcknowledgmentStatusHandler(registry *ControllerRegistry, key ControllerKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controllers, ok := registry.lookup(key)
		if !ok || controllers.Status == nil {
			writeError(w, http.StatusServiceUnavailable, "service unavailable")
			return
		}
		limit := 0
		if raw := r.URL.Query().Get("partition_limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 || parsed > defaultStatusPartitionLimit {
				writeError(w, http.StatusBadRequest, "invalid request")
				return
			}
			limit = parsed
		}
		writeJSON(w, http.StatusOK, controllers.Status.StatusSnapshot(limit))
	})
}

// ControllerRegistry connects HTTP routing to active input components without
// exposing a Kafka client to HTTP goroutines.
type ControllerRegistry struct {
	mu          sync.RWMutex
	controllers map[ControllerKey]controllerRegistration
	nextOwner   uint64
}

type controllerRegistration struct {
	controllers Controllers
	owner       uint64
	limiters    map[string]*ControlRateLimiter
}

// ControllerRegistration is an opaque ownership lease. Only the lease that
// installed an entry can remove it; repeated or stale release is harmless.
type ControllerRegistration struct {
	registry *ControllerRegistry
	key      ControllerKey
	owner    uint64
}

// GlobalControllerRegistry bridges Bento-created connector instances with the
// stream HTTP mux. Entries are strictly lifecycle-scoped and are removed when
// the owning connector closes.
var GlobalControllerRegistry = NewControllerRegistry()

func NewControllerRegistry() *ControllerRegistry {
	return &ControllerRegistry{controllers: make(map[ControllerKey]controllerRegistration)}
}

func (r *ControllerRegistry) Register(key ControllerKey, controllers Controllers) (*ControllerRegistration, error) {
	if r == nil {
		return nil, errors.New("nil controller registry")
	}
	if err := key.validate(); err != nil {
		return nil, err
	}
	if controllers.Acknowledgments == nil && controllers.Offsets == nil && controllers.Status == nil {
		return nil, errors.New("at least one controller is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.controllers[key]; exists {
		return nil, fmt.Errorf("controllers already registered")
	}
	r.nextOwner++
	if r.nextOwner == 0 {
		r.nextOwner++
	}
	owner := r.nextOwner
	r.controllers[key] = controllerRegistration{controllers: controllers, owner: owner, limiters: make(map[string]*ControlRateLimiter)}
	return &ControllerRegistration{registry: r, key: key, owner: owner}, nil
}

// RateLimiter returns lifecycle-scoped limiter state only for a registered
// component. The three fixed class names bound storage per registration.
func (r *ControllerRegistry) RateLimiter(key ControllerKey, class string, requestsPerSecond float64, burst int) (*ControlRateLimiter, bool) {
	if class != "ack" && class != "reset-plan" && class != "reset-execute" {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	registration, ok := r.controllers[key]
	if !ok {
		return nil, false
	}
	if limiter := registration.limiters[class]; limiter != nil {
		limiter.reconfigure(requestsPerSecond, burst, class == "ack")
		return limiter, true
	}
	var limiter *ControlRateLimiter
	if class == "ack" {
		limiter = NewAcknowledgmentRateLimiter(requestsPerSecond, burst)
	} else {
		limiter = NewResetRateLimiter(requestsPerSecond, burst)
	}
	registration.limiters[class] = limiter
	r.controllers[key] = registration
	return limiter, true
}

func (r *ControllerRegistry) unregister(key ControllerKey, owner uint64) bool {
	if r == nil || owner == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	registration, exists := r.controllers[key]
	if !exists || registration.owner != owner {
		return false
	}
	delete(r.controllers, key)
	return true
}

func (r *ControllerRegistration) Unregister() bool {
	if r == nil {
		return false
	}
	return r.registry.unregister(r.key, r.owner)
}

func (r *ControllerRegistry) lookup(key ControllerKey) (Controllers, bool) {
	if r == nil {
		return Controllers{}, false
	}
	r.mu.RLock()
	registration, ok := r.controllers[key]
	r.mu.RUnlock()
	return registration.controllers, ok
}

func (r *ControllerRegistry) StatusSnapshot(key ControllerKey, limit int) (ExternalAckStatus, bool) {
	controllers, ok := r.lookup(key)
	if !ok || controllers.Status == nil {
		return ExternalAckStatus{}, false
	}
	return controllers.Status.StatusSnapshot(limit), true
}

type HandlerLimits struct {
	MaxRequestBytes int64
	MaxTokens       int
	MaxTokenBytes   int
	MaxResetTargets int
	// RateLimiter is intentionally scoped to a single control class. When nil,
	// each handler receives an independent safe default limiter.
	RateLimiter *ControlRateLimiter
	// RateLimitConfig is evaluated on each request so live configuration
	// changes update an existing handler without resetting its allowance.
	RateLimitConfig func() (requestsPerSecond float64, burst int)
}

func (l HandlerLimits) withDefaults() HandlerLimits {
	if l.MaxRequestBytes <= 0 {
		l.MaxRequestBytes = defaultMaxRequestBytes
	}
	if l.MaxTokens <= 0 {
		l.MaxTokens = defaultMaxTokens
	}
	if l.MaxTokenBytes <= 0 {
		l.MaxTokenBytes = defaultMaxTokenBytes
	}
	if l.MaxResetTargets <= 0 {
		l.MaxResetTargets = defaultMaxResetTargets
	}
	return l
}

type ackRequest struct {
	Tokens []string `json:"tokens"`
}

type ackResponse struct {
	Results []AckResult `json:"results"`
}

func NewAcknowledgmentHandler(registry *ControllerRegistry, key ControllerKey, limits HandlerLimits) http.Handler {
	limits = limits.withDefaults()
	if limits.RateLimiter == nil {
		limits.RateLimiter = NewAcknowledgmentRateLimiter(0, 0)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if limits.RateLimitConfig != nil {
			rate, burst := limits.RateLimitConfig()
			limits.RateLimiter.reconfigure(rate, burst, true)
		}
		if ok, retry := limits.RateLimiter.allow(); !ok {
			writeRateLimitError(w, retry)
			return
		}

		var request ackRequest
		if err := decodeStrictJSON(w, r, limits.MaxRequestBytes, &request); err != nil {
			writeDecodeError(w, err)
			return
		}
		if len(request.Tokens) == 0 {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		if len(request.Tokens) > limits.MaxTokens {
			writeError(w, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		for _, token := range request.Tokens {
			if token == "" || len(token) > limits.MaxTokenBytes {
				writeError(w, http.StatusBadRequest, "invalid request")
				return
			}
		}

		controllers, ok := registry.lookup(key)
		if !ok || controllers.Acknowledgments == nil {
			writeError(w, http.StatusServiceUnavailable, "service unavailable")
			return
		}
		results, err := controllers.Acknowledgments.Acknowledge(r.Context(), request.Tokens)
		if err != nil || len(results) != len(request.Tokens) || !validAckResults(results) {
			writeError(w, http.StatusServiceUnavailable, "service unavailable")
			return
		}
		writeJSON(w, ackHTTPStatus(results), ackResponse{Results: results})
	})
}

func validAckResults(results []AckResult) bool {
	for _, result := range results {
		switch result.Disposition {
		case AckApplied, AckDuplicate, AckQueued, AckInvalid, AckStale, AckExpired, AckUnavailable:
		default:
			return false
		}
	}
	return true
}

func ackHTTPStatus(results []AckResult) int {
	first := ackDispositionHTTPStatus(results[0].Disposition)
	for _, result := range results[1:] {
		if ackDispositionHTTPStatus(result.Disposition) != first {
			return http.StatusMultiStatus
		}
	}
	return first
}

func ackDispositionHTTPStatus(disposition AckDisposition) int {
	switch disposition {
	case AckApplied, AckDuplicate:
		return http.StatusOK
	case AckQueued:
		return http.StatusAccepted
	case AckInvalid:
		return http.StatusBadRequest
	case AckStale:
		return http.StatusConflict
	case AckExpired:
		return http.StatusGone
	default:
		return http.StatusServiceUnavailable
	}
}

// ControlError allows the control-plane implementation to select a safe HTTP
// class without exposing an internal Kafka or infrastructure error.
type ControlError struct {
	Status int
	Err    error
}

func (e *ControlError) Error() string {
	if e.Err == nil {
		return http.StatusText(e.Status)
	}
	return e.Err.Error()
}

func (e *ControlError) Unwrap() error { return e.Err }

func NewResetPlanHandler(registry *ControllerRegistry, key ControllerKey, limits HandlerLimits) http.Handler {
	limits = limits.withDefaults()
	if limits.RateLimiter == nil {
		limits.RateLimiter = NewResetRateLimiter(0, 0)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if limits.RateLimitConfig != nil {
			rate, burst := limits.RateLimitConfig()
			limits.RateLimiter.reconfigure(rate, burst, false)
		}
		if ok, retry := limits.RateLimiter.allow(); !ok {
			writeRateLimitError(w, retry)
			return
		}
		var request ResetPlanRequest
		if err := decodeStrictJSON(w, r, limits.MaxRequestBytes, &request); err != nil {
			writeDecodeError(w, err)
			return
		}
		if len(request.Targets) > limits.MaxResetTargets {
			writeError(w, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		if err := validateResetPlan(request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		controllers, ok := registry.lookup(key)
		if !ok || controllers.Offsets == nil {
			writeError(w, http.StatusServiceUnavailable, "service unavailable")
			return
		}
		plan, err := controllers.Offsets.PlanReset(r.Context(), request)
		if err != nil {
			writeControlError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, plan)
	})
}

func NewResetExecuteHandler(registry *ControllerRegistry, key ControllerKey, limits HandlerLimits) http.Handler {
	limits = limits.withDefaults()
	if limits.RateLimiter == nil {
		limits.RateLimiter = NewResetRateLimiter(0, 0)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if limits.RateLimitConfig != nil {
			rate, burst := limits.RateLimitConfig()
			limits.RateLimiter.reconfigure(rate, burst, false)
		}
		if ok, retry := limits.RateLimiter.allow(); !ok {
			writeRateLimitError(w, retry)
			return
		}
		var request ResetExecuteRequest
		if err := decodeStrictJSON(w, r, limits.MaxRequestBytes, &request); err != nil {
			writeDecodeError(w, err)
			return
		}
		if strings.TrimSpace(request.PlanID) == "" || len(request.PlanID) > limits.MaxTokenBytes {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		controllers, ok := registry.lookup(key)
		if !ok || controllers.Offsets == nil {
			writeError(w, http.StatusServiceUnavailable, "service unavailable")
			return
		}
		execution, err := controllers.Offsets.ExecuteReset(r.Context(), request)
		if err != nil {
			writeControlError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, execution)
	})
}

func validateResetPlan(request ResetPlanRequest) error {
	if strings.TrimSpace(request.ConsumerGroup) == "" || strings.TrimSpace(request.Reason) == "" || len(request.Targets) == 0 {
		return errors.New("invalid reset plan")
	}
	seen := make(map[string]struct{}, len(request.Targets))
	for _, target := range request.Targets {
		if strings.TrimSpace(target.Topic) == "" || target.Partition < 0 || (target.Offset == nil) == (target.TimestampMS == nil) {
			return errors.New("invalid reset target")
		}
		if target.Offset != nil && *target.Offset < 0 {
			return errors.New("invalid offset")
		}
		if target.TimestampMS != nil && *target.TimestampMS < 0 {
			return errors.New("invalid timestamp")
		}
		identity := fmt.Sprintf("%s\x00%d", target.Topic, target.Partition)
		if _, exists := seen[identity]; exists {
			return errors.New("duplicate reset target")
		}
		seen[identity] = struct{}{}
	}
	return nil
}

var errRequestTooLarge = errors.New("request too large")

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return errRequestTooLarge
		}
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	if errors.Is(err, errRequestTooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid request")
}

func writeControlError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var controlError *ControlError
	if errors.As(err, &controlError) {
		switch controlError.Status {
		case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusGone, http.StatusServiceUnavailable:
			status = controlError.Status
		}
	}
	message := "operation failed"
	if status == http.StatusServiceUnavailable {
		message = "service unavailable"
	}
	writeError(w, status, message)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeRateLimitError(w http.ResponseWriter, retry time.Duration) {
	seconds := int64((retry + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
