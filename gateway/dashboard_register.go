package gateway

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/TykTechnologies/tyk/header"
)

var dashLog = log.WithField("prefix", "dashboard")

type NodeResponseOK struct {
	Status  string
	Message map[string]string
	Nonce   string
}

type DashboardServiceSender interface {
	Init() error
	Register() error
	DeRegister() error
	StartBeating() error
	StopBeating()
	Ping() error
	NotifyDashboardOfEvent(interface{}) error
}

type HTTPDashboardHandler struct {
	RegistrationEndpoint    string
	DeRegistrationEndpoint  string
	HeartBeatEndpoint       string
	KeyQuotaTriggerEndpoint string

	Secret string

	heartBeatStopSentinel bool
	Gw                    *Gateway `json:"-"`
}

var dashClient *http.Client

func (gw *Gateway) initialiseClient() *http.Client {
	if dashClient == nil {
		dashClient = &http.Client{
			Timeout: 30 * time.Second,
		}

		if gw.GetConfig().HttpServerOptions.UseSSL {
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

	if err := gw.DashService.Register(); err != nil {
		dashLog.Error("Could not register: ", err)
	} else {
		go func() {
			beatErr := gw.DashService.StartBeating()
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
		err := fmt.Errorf("Unexpected status code while trying to notify dashboard of a key limit quota trigger.. Got %d", resp.StatusCode)
		log.Error(err)
		return err
	}

	val := NodeResponseOK{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return err
	}

	h.Gw.ServiceNonceMutex.Lock()
	h.Gw.ServiceNonce = val.Nonce
	h.Gw.ServiceNonceMutex.Unlock()

	return nil
}

func (h *HTTPDashboardHandler) Register() error {
	dashLog.Info("Registering gateway node with Dashboard")
	req := h.newRequest(http.MethodGet, h.RegistrationEndpoint)
	c := h.Gw.initialiseClient()

	resp, err := c.Do(req)

	if err != nil {
		dashLog.Errorf("Request failed with error %v; retrying in 5s", err)
		time.Sleep(time.Second * 5)
		return h.Register()
	} else if resp.StatusCode == http.StatusConflict {
		dashLog.Debug("Node is already registered")
		return nil
	} else if resp != nil && resp.StatusCode != 200 {
		dashLog.Errorf("Response failed with code %d; retrying in 5s", resp.StatusCode)
		time.Sleep(time.Second * 5)
		return h.Register()
	}

	defer resp.Body.Close()
	val := NodeResponseOK{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return err
	}

	// Set the NodeID
	var found bool
	nodeID, found := val.Message["NodeID"]
	h.Gw.SetNodeID(nodeID)
	if !found {
		dashLog.Error("Failed to register node, retrying in 5s")
		time.Sleep(time.Second * 5)
		return h.Register()
	}

	dashLog.WithField("id", h.Gw.GetNodeID()).Info("Node Registered")

	// Set the nonce
	h.Gw.ServiceNonceMutex.Lock()
	h.Gw.ServiceNonce = val.Nonce
	h.Gw.ServiceNonceMutex.Unlock()
	dashLog.Debug("Registration Finished: Nonce Set: ", val.Nonce)

	return nil
}

func (h *HTTPDashboardHandler) Ping() error {
	return h.sendHeartBeat(
		h.newRequest(http.MethodGet, h.HeartBeatEndpoint),
		h.Gw.initialiseClient())
}

func (h *HTTPDashboardHandler) StartBeating() error {

	req := h.newRequest(http.MethodGet, h.HeartBeatEndpoint)

	client := h.Gw.initialiseClient()

	for !h.heartBeatStopSentinel {
		if err := h.sendHeartBeat(req, client); err != nil {
			dashLog.Warning(err)
		}
		time.Sleep(time.Second * 2)
	}

	dashLog.Info("Stopped Heartbeat")
	h.heartBeatStopSentinel = false
	return nil
}

func (h *HTTPDashboardHandler) StopBeating() {
	h.heartBeatStopSentinel = true
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

func (h *HTTPDashboardHandler) sendHeartBeat(req *http.Request, client *http.Client) error {
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
		return h.Gw.DashService.Register()
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New("dashboard is down? Heartbeat non-200 response")
	}
	val := NodeResponseOK{}
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
		return fmt.Errorf("deregister request failed with error %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deregister request failed with status %v", resp.StatusCode)
	}

	val := NodeResponseOK{}
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
