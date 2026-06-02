package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/header"
)

var dashLog = log.WithField("prefix", "dashboard")

type NodeResponse struct {
	Status  string
	Message any
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

func (gw *Gateway) reLogin() {
	if !gw.GetConfig().UseDBAppConfigs {
		return
	}

	dashLog.Info("Registering node (again).")
	gw.DashService.StopBeating()
	if err := gw.DashService.DeRegister(); err != nil {
		dashLog.Error("Could not deregister: ", err)
	}

	time.Sleep(5 * time.Second)

	if err := gw.DashService.Register(gw.ctx); err != nil {
		dashLog.Error("Could not register: ", err)
	} else {
		go func() {
			beatErr := gw.DashService.StartBeating(gw.ctx)
			if beatErr != nil {
				dashLog.Error("Could not start beating. ", beatErr.Error())
			}
		}()
	}

	dashLog.Info("Recovering configurations, reloading...")
	gw.reloadURLStructure(nil)
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
		err := fmt.Errorf("unexpected status code while trying to notify dashboard of a key limit quota trigger.. Got %d", resp.StatusCode)
		log.Error(err)
		return err
	}

	val := NodeResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return err
	}

	h.Gw.ServiceNonceMutex.Lock()
	h.Gw.ServiceNonce = val.Nonce
	h.Gw.ServiceNonceMutex.Unlock()

	return nil
}

// parseRegistrationResponse extracts the NodeID from a successful registration
// response body. It returns ("", false) when a retry should be attempted.
func parseRegistrationResponse(statusCode int, val NodeResponse) (nodeID string, ok bool) {
	// 409 with Status != "OK" means lock contention or Redis failure — retry.
	if statusCode == http.StatusConflict && val.Status != "OK" {
		dashLog.Warning("Registration deferred (409 with status: ", val.Status, "); retrying in 5s")
		return "", false
	}

	msgMap, ok := val.Message.(map[string]interface{})
	if !ok {
		dashLog.Error("Failed to register node, retrying in 5s")
		return "", false
	}

	nodeID, ok = msgMap["NodeID"].(string)
	if !ok || nodeID == "" {
		dashLog.Error("Failed to register node, retrying in 5s")
		return "", false
	}

	return nodeID, true
}

func (h *HTTPDashboardHandler) Register(ctx context.Context) error {
	dashLog.Info("Registering gateway node with Dashboard")

	for {
		registered, err := h.attemptRegistration(ctx)
		if err != nil {
			return err
		}
		if registered {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (h *HTTPDashboardHandler) attemptRegistration(ctx context.Context) (registered bool, err error) {
	req := h.newRequestWithContext(ctx, http.MethodGet, h.RegistrationEndpoint)
	req.Header.Set(header.XTykSessionID, h.Gw.SessionID)

	resp, err := h.Gw.initialiseClient().Do(req)
	if err != nil {
		dashLog.Errorf("Request failed with error %v; retrying in 5s", err)
		return false, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		dashLog.Errorf("Response failed with code %d; retrying in 5s", resp.StatusCode)
		return false, nil
	}

	var val NodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return false, err
	}

	nodeID, ok := parseRegistrationResponse(resp.StatusCode, val)
	if !ok {
		return false, nil
	}

	h.Gw.SetNodeID(nodeID)
	dashLog.WithField("id", h.Gw.GetNodeID()).Info("Node Registered")

	h.Gw.ServiceNonceMutex.Lock()
	h.Gw.ServiceNonce = val.Nonce
	h.Gw.ServiceNonceMutex.Unlock()
	dashLog.Debug("Registration Finished: Nonce Set: ", val.Nonce)
	h.Gw.DoReloadWithRetry(ctx)

	return true, nil
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

	for {
		select {
		case <-ctx.Done():
			dashLog.Info("Heartbeat stopped due to context cancellation")
			return nil
		default:
			if h.isHeartBeatStopped() {
				dashLog.Info("Stopped Heartbeat")
				return nil
			}
			if err := h.sendHeartBeat(req, client, ctx); err != nil {
				dashLog.Warning(err)
			}
			time.Sleep(time.Second * 2)
		}
	}
}

func (h *HTTPDashboardHandler) StopBeating() {
	atomic.SwapInt32(&h.heartBeatStopSentinel, HeartBeatStopped)
}

func (h *HTTPDashboardHandler) newRequest(method, endpoint string) *http.Request {
	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		panic(err)
	}
	h.addHeaderToRequest(req)
	return req
}

func (h *HTTPDashboardHandler) newRequestWithContext(ctx context.Context, method, endpoint string) *http.Request {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		panic(err)
	}

	h.addHeaderToRequest(req)
	return req
}

func (h *HTTPDashboardHandler) addHeaderToRequest(req *http.Request) {
	req.Header.Set("authorization", h.Secret)
	req.Header.Set(header.XTykHostname, h.Gw.hostDetails.Hostname)
	req.Header.Set(header.XTykSessionID, h.Gw.SessionID)
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
		return h.Gw.DashService.Register(ctx)
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New("dashboard is down? Heartbeat non-200 response")
	}
	val := NodeResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return err
	}

	// Set the nonce
	h.Gw.ServiceNonceMutex.Lock()
	h.Gw.ServiceNonce = val.Nonce
	h.Gw.ServiceNonceMutex.Unlock()
	//log.Debug("Heartbeat Finished: Nonce Set: ", h.Gw.ServiceNonce)

	return nil
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
		return fmt.Errorf("deregister request failed with error %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deregister request failed with status %d", resp.StatusCode)
	}

	val := NodeResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return err
	}

	// Set the nonce
	h.Gw.ServiceNonceMutex.Lock()
	h.Gw.ServiceNonce = val.Nonce
	h.Gw.ServiceNonceMutex.Unlock()
	dashLog.Info("De-registered.")

	return nil
}
