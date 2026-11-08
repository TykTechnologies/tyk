package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/model"
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
	CertificatesEndpoint    string

	Secret string

	heartBeatStopSentinel int32

	// certReportMu serialises certificate reports, so an older report never arrives last.
	certReportMu sync.Mutex
	// certReportQueued is set while a report waits for the one in flight, so reloads during a
	// slow request queue a single report instead of one each.
	certReportQueued atomic.Bool
	// certReportFailed is set when a report couldn't be delivered. The next successful heartbeat
	// sends it again, so the Dashboard doesn't count a working Gateway as not reporting.
	certReportFailed atomic.Bool
	// certReportUnsupported is set when the Dashboard is too old to accept certificate reports,
	// and cleared when the Gateway registers again.
	certReportUnsupported atomic.Bool

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
	h.CertificatesEndpoint = h.Gw.buildDashboardConnStr("/system/node/certificates")

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
	h.Gw.nodeMetadata().setHeaders(req.Header)

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

	// The Dashboard drops the report of a node ID it gives to a newly registering Gateway,
	// and it may have been upgraded since the last registration.
	h.certReportUnsupported.Store(false)
	h.queueCertificateReport()

	return true, nil
}

// reportCertificatesToDashboard sends the certificates the Gateway uses to the Dashboard,
// when the Gateway is connected directly to it. Data Plane Gateways report through MDCB instead.
func (gw *Gateway) reportCertificatesToDashboard() {
	conf := gw.GetConfig()
	if !conf.UseDBAppConfigs || conf.SlaveOptions.UseRPC {
		return
	}

	if h, ok := gw.DashService.(*HTTPDashboardHandler); ok {
		h.queueCertificateReport()
	}
}

// queueCertificateReport sends a report in the background. The report is built when it's sent, so
// a report already waiting will carry the latest list, and another one isn't needed.
func (h *HTTPDashboardHandler) queueCertificateReport() {
	if !h.certReportQueued.CompareAndSwap(false, true) {
		return
	}

	go func() {
		h.certReportMu.Lock()
		defer h.certReportMu.Unlock()
		h.certReportQueued.Store(false)

		if err := h.sendCertificateReport(); err != nil {
			dashLog.WithError(err).Warning("Could not report the certificates in use to the Dashboard, will retry after the next heartbeat")
		}
	}()
}

// ReportCertificates sends the certificates the Gateway uses to POST /system/node/certificates.
// An older Dashboard answers 404, and the Gateway doesn't try again until it next registers.
func (h *HTTPDashboardHandler) ReportCertificates() error {
	h.certReportMu.Lock()
	defer h.certReportMu.Unlock()
	return h.sendCertificateReport()
}

func (h *HTTPDashboardHandler) sendCertificateReport() error {
	err := h.doSendCertificateReport()
	h.certReportFailed.Store(err != nil)
	return err
}

func (h *HTTPDashboardHandler) doSendCertificateReport() error {
	if h.certReportUnsupported.Load() || h.CertificatesEndpoint == "" {
		return nil
	}

	body, err := json.Marshal(model.CertificateReport{Certificates: h.Gw.certificateReport()})
	if err != nil {
		return err
	}

	ctx := h.Gw.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.CertificatesEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	h.addHeaderToRequest(req)
	req.Header.Set(header.ContentType, header.ApplicationJSON)
	req.Header.Set(header.XTykNodeID, h.Gw.GetNodeID())
	h.Gw.ServiceNonceMutex.RLock()
	req.Header.Set(header.XTykNonce, h.Gw.ServiceNonce)
	h.Gw.ServiceNonceMutex.RUnlock()

	resp, err := h.Gw.initialiseClient().Do(req)
	if err != nil {
		return fmt.Errorf("certificate report request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		h.certReportUnsupported.Store(true)
		dashLog.Info("The Dashboard doesn't accept reports of the certificates in use. Upgrade it to see which Gateways use each certificate.")
		return nil
	default:
		return fmt.Errorf("certificate report failed with status %d", resp.StatusCode)
	}

	val := NodeResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return err
	}
	if val.Nonce != "" {
		h.Gw.ServiceNonceMutex.Lock()
		h.Gw.ServiceNonce = val.Nonce
		h.Gw.ServiceNonceMutex.Unlock()
	}

	dashLog.Debug("Reported the certificates in use to the Dashboard")
	return nil
}

// Ping is the dashboard liveness probe behind /hello and /ready. It must
// never block on, nor trigger, node re-registration (TT-17486): a 403 means
// the dashboard is reachable but does not recognise this node (e.g. its
// session store is unavailable), and recovery from that state is owned by
// the heartbeat loop, not by the probe.
func (h *HTTPDashboardHandler) Ping() error {
	ctx := h.Gw.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	err := h.doHeartBeat(
		h.newRequestWithContext(ctx, http.MethodGet, h.HeartBeatEndpoint),
		h.Gw.initialiseClient())
	if errors.Is(err, errHeartBeatForbidden) {
		return nil
	}
	return err
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

// errHeartBeatForbidden signals a 403 heartbeat response: dashboard reachable but node not recognised.
var errHeartBeatForbidden = errors.New("heartbeat rejected: node not recognised by the dashboard")

func (h *HTTPDashboardHandler) sendHeartBeat(req *http.Request, client *http.Client, ctx context.Context) error {
	err := h.doHeartBeat(req, client)
	if errors.Is(err, errHeartBeatForbidden) {
		return h.Gw.DashService.Register(ctx)
	}
	return err
}

func (h *HTTPDashboardHandler) doHeartBeat(req *http.Request, client *http.Client) error {
	req.Header.Set(header.XTykNodeID, h.Gw.GetNodeID())
	h.Gw.ServiceNonceMutex.RLock()
	req.Header.Set(header.XTykNonce, h.Gw.ServiceNonce)
	h.Gw.ServiceNonceMutex.RUnlock()
	// Refreshed on every send: StartBeating reuses req across heartbeats.
	h.Gw.nodeMetadata().setHeaders(req.Header)

	resp, err := client.Do(req)
	if err != nil {
		return errors.New("dashboard is down? Heartbeat is failing")
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return errHeartBeatForbidden
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

	if h.certReportFailed.CompareAndSwap(true, false) {
		h.queueCertificateReport()
	}

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
