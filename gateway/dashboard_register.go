package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gocraft/health"

	"github.com/TykTechnologies/tyk/header"
)

var dashLog = log.WithField("prefix", "dashboard")

// Swappable for tests. Mutating this package var is not goroutine-safe;
// tests that override it must not run in parallel.
// Preferred long-term approach (if wider blast radius is acceptable):
// inject the recorder on HTTPDashboardHandler instead of using global state.
var recordReRegisterCircuitOpenMetric = func(nodeID string, consecutive int, delay time.Duration) {
	job := instrument.NewJob("DashboardRecovery")
	job.EventKv("re_register_circuit_open", health.Kvs{
		"node_id":       nodeID,
		"consecutive":   strconv.Itoa(consecutive),
		"next_retry_in": delay.String(),
	})
}

type NodeResponseOK struct {
	Status  string
	Message map[string]string
	Nonce   string
}

type DashboardServiceSender interface {
	Init() error
	Register(ctx context.Context) error
	DeRegister() error
	StartBeating(ctx context.Context) error
	StopBeating()
	Ping() error
	NotifyDashboardOfEvent(interface{}) error
}

// Constants for heartBeatStopSentinel indicators.
//
// Go 1.17 adds atomic.Value.Swap which is great, but 1.19
// adds atomic.Bool and other types. This is a go <1.13 cludge.
const (
	// HeartBeatStarted Zero value - the handlers started
	HeartBeatStarted = 0

	// HeartBeatStopped value - the handlers invoked shutdown
	HeartBeatStopped = 1
)

type HTTPDashboardHandler struct {
	RegistrationEndpoint    string
	DeRegistrationEndpoint  string
	HeartBeatEndpoint       string
	KeyQuotaTriggerEndpoint string

	Secret string

	heartBeatStopSentinel int32

	reRegisterMu          sync.Mutex
	reRegisterWindowStart time.Time
	reRegisterConsecutive int
	retryRng              *rand.Rand
	now                   func() time.Time

	Gw *Gateway `json:"-"`
}

var dashClient *http.Client

// resetDashboardClient resets the global dashboard client for tests
func (gw *Gateway) resetDashboardClient() {
	dashClient = nil
}

func (gw *Gateway) initialiseClient() *http.Client {
	if dashClient == nil {
		conf := gw.GetConfig()
		timeout := conf.DBAppConfOptions.ConnectionTimeout

		// I don't think this is the appropriate place for this. I recommend we look at
		// something like https://github.com/mcuadros/go-defaults to normalize all our defaults.
		if timeout < 1 {
			timeout = 30
		}

		dashClient = &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		}

		if conf.HttpServerOptions.UseSSL {
			// Setup HTTPS client
			tlsConfig := &tls.Config{
				InsecureSkipVerify: gw.GetConfig().HttpServerOptions.SSLInsecureSkipVerify,
				MinVersion:         gw.GetConfig().HttpServerOptions.MinVersion,
				MaxVersion:         gw.GetConfig().HttpServerOptions.MaxVersion,
			}

			dashClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
		}
	}

	return dashClient
}

func (h *HTTPDashboardHandler) Init() error {
	h.RegistrationEndpoint = h.Gw.buildDashboardConnStr("/register/node")
	h.DeRegistrationEndpoint = h.Gw.buildDashboardConnStr("/system/node")
	h.HeartBeatEndpoint = h.Gw.buildDashboardConnStr("/register/ping")
	h.KeyQuotaTriggerEndpoint = h.Gw.buildDashboardConnStr("/system/key/quota_trigger")

	if h.Secret = h.Gw.GetConfig().NodeSecret; h.Secret == "" {
		dashLog.Fatal("Node secret is not set, required for dashboard connection")
	}
	return nil
}

// NotifyDashboardOfEvent acts as a form of event which informs the
// dashboard of a key which has reached a certain usage quota
func (h *HTTPDashboardHandler) NotifyDashboardOfEvent(event interface{}) error {

	meta, ok := event.(EventTriggerExceededMeta)
	if !ok {
		return errors.New("event type is currently not supported as a notification to the dashboard")
	}

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(meta); err != nil {
		log.Errorf("Could not decode event metadata :%v", err)
		return err
	}

	req, err := http.NewRequest(http.MethodPost, h.KeyQuotaTriggerEndpoint, &b)
	if err != nil {
		log.Errorf("Could not create request.. %v", err)
		return err
	}

	req.Header.Set("authorization", h.Secret)
	req.Header.Set(header.XTykNodeID, h.Gw.GetNodeID())
	h.Gw.ServiceNonceMutex.RLock()
	req.Header.Set(header.XTykNonce, h.Gw.ServiceNonce)
	h.Gw.ServiceNonceMutex.RUnlock()

	c := h.Gw.initialiseClient()

	resp, err := c.Do(req)
	if err != nil {
		log.Errorf("Request failed with error %v", err)
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("Unexpected status code while trying to notify dashboard of a key limit quota trigger.. Got %d", resp.StatusCode)
		log.Error(err)
		return err
	}

	val := NodeResponseOK{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return err
	}

	h.setServiceNonceIfPresent("quota_trigger", val.Nonce)

	return nil
}

func (h *HTTPDashboardHandler) Register(ctx context.Context) error {
	// Keep retrying until we receive a complete registration payload.
	// Registration is only considered successful when both NodeID and nonce are present.
	// We intentionally use the same jittered exponential schedule as heartbeat recovery
	// to avoid synchronized 5s retry cohorts during fleet-wide reconnect events.
	attempt := 0
	for {
		attempt++
		dashLog.Info("Registering gateway node with Dashboard")

		req := h.newRequest(http.MethodGet, h.RegistrationEndpoint)
		req.Header.Set(header.XTykSessionID, h.Gw.SessionID)

		c := h.Gw.initialiseClient()
		resp, err := c.Do(req)

		if err != nil {
			delay := h.nextRegisterRetryDelay(attempt)
			dashLog.Errorf("Request failed with error %v; retrying in %s", err, delay)
			if err := sleepWithContext(ctx, delay); err != nil {
				return err
			}
			continue
		}

		if resp.StatusCode != http.StatusOK {
			// Treat all non-200 responses (including 409) as retriable.
			// A 409 indicates an in-flight registration and does not return a usable nonce.
			_ = resp.Body.Close()
			delay := h.nextRegisterRetryDelay(attempt)
			dashLog.Errorf("Response failed with code %d; retrying in %s", resp.StatusCode, delay)
			if err := sleepWithContext(ctx, delay); err != nil {
				return err
			}
			continue
		}

		val := NodeResponseOK{}
		if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
			_ = resp.Body.Close()
			return err
		}
		_ = resp.Body.Close()

		nodeID, found := val.Message["NodeID"]
		if !found || nodeID == "" {
			delay := h.nextRegisterRetryDelay(attempt)
			dashLog.Errorf("Failed to register node (missing NodeID), retrying in %s", delay)
			if err := sleepWithContext(ctx, delay); err != nil {
				return err
			}
			continue
		}

		if !h.setServiceNonceIfPresent("register", val.Nonce) {
			delay := h.nextRegisterRetryDelay(attempt)
			dashLog.Errorf("Registration response missing nonce; retrying in %s", delay)
			if err := sleepWithContext(ctx, delay); err != nil {
				return err
			}
			continue
		}

		h.Gw.SetNodeID(nodeID)
		dashLog.WithField("id", h.Gw.GetNodeID()).Info("Node Registered")
		dashLog.Debug("Registration Finished: Nonce Set: ", val.Nonce)

		return nil
	}
}

func (h *HTTPDashboardHandler) Ping() error {
	return h.sendHeartBeat(
		h.newRequest(http.MethodGet, h.HeartBeatEndpoint),
		h.Gw.initialiseClient(),
		context.Background())
}

func (h *HTTPDashboardHandler) isHeartBeatStopped() bool {
	return atomic.LoadInt32(&h.heartBeatStopSentinel) == HeartBeatStopped
}

func (h *HTTPDashboardHandler) StartBeating(ctx context.Context) error {
	atomic.SwapInt32(&h.heartBeatStopSentinel, HeartBeatStarted)

	req := h.newRequest(http.MethodGet, h.HeartBeatEndpoint)

	client := h.Gw.initialiseClient()

	for !h.isHeartBeatStopped() {
		select {
		case <-ctx.Done():
			dashLog.Info("Stopped Heartbeat due to context cancellation")
			return nil
		default:
		}
		if err := h.sendHeartBeat(req, client, ctx); err != nil {
			dashLog.Warning(err)
		}
		time.Sleep(time.Second * 2)
	}

	dashLog.Info("Stopped Heartbeat")
	return nil
}

func (h *HTTPDashboardHandler) StopBeating() {
	atomic.SwapInt32(&h.heartBeatStopSentinel, HeartBeatStopped)
}

func (h *HTTPDashboardHandler) newRequest(method, endpoint string) *http.Request {
	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("authorization", h.Secret)
	req.Header.Set(header.XTykHostname, h.Gw.hostDetails.Hostname)
	req.Header.Set(header.XTykSessionID, h.Gw.SessionID)
	return req
}

func (h *HTTPDashboardHandler) sendHeartBeat(req *http.Request, client *http.Client, ctx context.Context) error {
	req.Header.Set(header.XTykNodeID, h.Gw.GetNodeID())
	h.Gw.ServiceNonceMutex.RLock()
	req.Header.Set(header.XTykNonce, h.Gw.ServiceNonce)
	h.Gw.ServiceNonceMutex.RUnlock()

	resp, err := client.Do(req)
	if err != nil {
		return errors.New("dashboard is down? Heartbeat is failing")
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		// A forbidden heartbeat means the registration/nonce state has drifted.
		// Re-register with controlled backoff to avoid fleet-wide retry storms.
		delay, consecutive := h.nextForbiddenRecoveryPlan()
		if consecutive > 1 {
			h.recordReRegisterCircuitOpen(consecutive, delay)
			dashLog.WithField("event", "re_register_circuit_open").
				WithField("node_id", h.Gw.GetNodeID()).
				WithField("consecutive", consecutive).
				WithField("next_retry_in", delay.String()).
				Warn("Dashboard heartbeat forbidden; backing off before re-register")
		}
		if err := sleepWithContext(ctx, delay); err != nil {
			return err
		}
		return h.Gw.DashService.Register(ctx)
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New("dashboard is down? Heartbeat non-200 response")
	}
	val := NodeResponseOK{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return err
	}

	if !h.setServiceNonceIfPresent("heartbeat", val.Nonce) {
		// Empty nonce guarantees the next authenticated request will fail.
		// Recover via controlled re-register instead of continuing with stale state.
		delay, consecutive := h.nextForbiddenRecoveryPlan()
		h.recordReRegisterCircuitOpen(consecutive, delay)
		dashLog.WithField("event", "heartbeat_empty_nonce").
			WithField("node_id", h.Gw.GetNodeID()).
			WithField("consecutive", consecutive).
			WithField("next_retry_in", delay.String()).
			Warn("Dashboard heartbeat returned empty nonce; backing off before re-register")
		if err := sleepWithContext(ctx, delay); err != nil {
			return err
		}
		return h.Gw.DashService.Register(ctx)
	}
	// log.Debug("Heartbeat Finished: Nonce Set: ", h.Gw.ServiceNonce)
	h.resetForbiddenRecoveryState()

	return nil
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

func (h *HTTPDashboardHandler) resetForbiddenRecoveryState() {
	h.reRegisterMu.Lock()
	defer h.reRegisterMu.Unlock()

	h.reRegisterConsecutive = 0
	h.reRegisterWindowStart = time.Time{}
}

// nextRegisterRetryDelay returns a capped retry schedule of
// 5s -> 10s -> 20s -> 40s -> 60s plus 0-1.5s jitter.
// A fixed 5s loop was avoided to prevent lockstep retries after shared outages.
func (h *HTTPDashboardHandler) nextRegisterRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}

	h.reRegisterMu.Lock()
	defer h.reRegisterMu.Unlock()

	if h.retryRng == nil {
		h.retryRng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	exp := attempt - 1
	if exp > 4 {
		exp = 4
	}

	delay := 5 * time.Second * time.Duration(1<<exp)
	if delay > 60*time.Second {
		delay = 60 * time.Second
	}

	jitter := time.Duration(h.retryRng.Int63n(int64(1500 * time.Millisecond)))
	delay += jitter
	if delay > 60*time.Second {
		delay = 60 * time.Second
	}

	return delay
}

func (h *HTTPDashboardHandler) setServiceNonceIfPresent(source, nonce string) bool {
	if nonce == "" {
		dashLog.WithField("source", source).Warn("Dashboard response missing nonce; keeping existing nonce")
		return false
	}

	h.Gw.ServiceNonceMutex.Lock()
	h.Gw.ServiceNonce = nonce
	h.Gw.ServiceNonceMutex.Unlock()

	return true
}

func (h *HTTPDashboardHandler) recordReRegisterCircuitOpen(consecutive int, delay time.Duration) {
	if consecutive <= 1 {
		return
	}

	nodeID := ""
	if h.Gw != nil {
		nodeID = h.Gw.GetNodeID()
	}
	recordReRegisterCircuitOpenMetric(nodeID, consecutive, delay)
}

// nextForbiddenRecoveryPlan returns a jittered delay and the retry count in the
// current 30-second window. It keeps first retries fast with jitter, then applies
// exponential backoff to prevent synchronized re-register stampedes.
func (h *HTTPDashboardHandler) nextForbiddenRecoveryPlan() (time.Duration, int) {
	now := time.Now()
	if h.now != nil {
		now = h.now()
	}

	h.reRegisterMu.Lock()
	defer h.reRegisterMu.Unlock()

	if h.retryRng == nil {
		h.retryRng = rand.New(rand.NewSource(now.UnixNano()))
	}

	if h.reRegisterWindowStart.IsZero() || now.Sub(h.reRegisterWindowStart) > 30*time.Second {
		h.reRegisterWindowStart = now
		h.reRegisterConsecutive = 0
	}

	h.reRegisterConsecutive++
	consecutive := h.reRegisterConsecutive

	// Always add jitter so fleet retries de-synchronize.
	jitterDelay := time.Second + time.Duration(h.retryRng.Int63n(int64(4*time.Second)))
	if consecutive <= 1 {
		return jitterDelay, consecutive
	}

	// Exponential backoff from second retry within the 30s window.
	exp := consecutive - 1
	if exp > 6 {
		exp = 6
	}
	backoffDelay := time.Duration(1<<exp) * time.Second
	if backoffDelay > 60*time.Second {
		backoffDelay = 60 * time.Second
	}

	backoffDelay += time.Duration(h.retryRng.Int63n(int64(time.Second)))
	if backoffDelay < jitterDelay {
		backoffDelay = jitterDelay
	}
	if backoffDelay > 60*time.Second {
		backoffDelay = 60 * time.Second
	}

	return backoffDelay, consecutive
}

func (h *HTTPDashboardHandler) DeRegister() error {
	req := h.newRequest(http.MethodDelete, h.DeRegistrationEndpoint)

	req.Header.Set(header.XTykNodeID, h.Gw.GetNodeID())
	h.Gw.ServiceNonceMutex.RLock()
	req.Header.Set(header.XTykNonce, h.Gw.ServiceNonce)
	h.Gw.ServiceNonceMutex.RUnlock()

	c := h.Gw.initialiseClient()
	resp, err := c.Do(req)

	if err != nil {
		return fmt.Errorf("deregister request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deregister request failed with status %v", resp.StatusCode)
	}

	val := NodeResponseOK{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return err
	}

	h.setServiceNonceIfPresent("deregister", val.Nonce)
	dashLog.Info("De-registered.")

	return nil
}
