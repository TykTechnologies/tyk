package gateway

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/headers"
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
	NotifyDashboardOfEvent(interface{}) error
}

type HTTPDashboardHandler struct {
	RegistrationEndpoint    string
	DeRegistrationEndpoint  string
	HeartBeatEndpoint       string
	KeyQuotaTriggerEndpoint string

	Secret string

	heartBeatStopSentinel bool
}

func initialiseClient(timeout time.Duration) *http.Client {
	client := &http.Client{
		Timeout: timeout,
	}

	if config.Global().HttpServerOptions.UseSSL {
		// Setup HTTPS client
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.Global().HttpServerOptions.SSLInsecureSkipVerify,
		}

		client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	return client
}

func reLogin() {
	if !config.Global().UseDBAppConfigs {
		return
	}

	dashLog.Info("Registering node (again).")
	DashService.StopBeating()
	if err := DashService.DeRegister(); err != nil {
		dashLog.Error("Could not deregister: ", err)
	}

	time.Sleep(5 * time.Second)

	if err := DashService.Register(); err != nil {
		dashLog.Error("Could not register: ", err)
	} else {
		go DashService.StartBeating()
	}

	dashLog.Info("Recovering configurations, reloading...")
	reloadURLStructure(nil)
}

func (h *HTTPDashboardHandler) Init() error {
	h.RegistrationEndpoint = buildConnStr("/register/node")
	h.DeRegistrationEndpoint = buildConnStr("/system/node")
	h.HeartBeatEndpoint = buildConnStr("/register/ping")
	h.KeyQuotaTriggerEndpoint = buildConnStr("/system/key/quota_trigger")

	if h.Secret = config.Global().NodeSecret; h.Secret == "" {
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
	req.Header.Set(headers.XTykNodeID, GetNodeID())
	req.Header.Set(headers.XTykNonce, ServiceNonce)

	c := initialiseClient(5 * time.Second)

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

	ServiceNonce = val.Nonce

	return nil
}

func (h *HTTPDashboardHandler) Register() error {
	dashLog.Info("Registering gateway node with Dashboard")
	req := h.newRequest(h.RegistrationEndpoint)
	c := initialiseClient(5 * time.Second)
	resp, err := c.Do(req)

	if err != nil {
		dashLog.Errorf("Request failed with error %v; retrying in 5s", err)
		time.Sleep(time.Second * 5)
		return h.Register()
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
	SetNodeID(nodeID)
	if !found {
		dashLog.Error("Failed to register node, retrying in 5s")
		time.Sleep(time.Second * 5)
		return h.Register()
	}

	dashLog.WithField("id", GetNodeID()).Info("Node Registered")

	// Set the nonce
	ServiceNonce = val.Nonce
	dashLog.Debug("Registration Finished: Nonce Set: ", ServiceNonce)

	return nil
}

func (h *HTTPDashboardHandler) StartBeating() error {

	req := h.newRequest(h.HeartBeatEndpoint)

	client := initialiseClient(5 * time.Second)

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

func (h *HTTPDashboardHandler) newRequest(endpoint string) *http.Request {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("authorization", h.Secret)
	req.Header.Set(headers.XTykHostname, hostDetails.Hostname)
	return req
}

func (h *HTTPDashboardHandler) sendHeartBeat(req *http.Request, client *http.Client) error {
	req.Header.Set(headers.XTykNodeID, GetNodeID())
	req.Header.Set(headers.XTykNonce, ServiceNonce)

	resp, err := client.Do(req)
	if err != nil {
		return errors.New("dashboard is down? Heartbeat is failing")
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("dashboard is down? Heartbeat non-200 response")
	}
	val := NodeResponseOK{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return err
	}

	// Set the nonce
	ServiceNonce = val.Nonce
	//log.Debug("Heartbeat Finished: Nonce Set: ", ServiceNonce)

	return nil
}

func (h *HTTPDashboardHandler) DeRegister() error {
	req := h.newRequest(h.DeRegistrationEndpoint)

	req.Header.Set(headers.XTykNodeID, GetNodeID())
	req.Header.Set(headers.XTykNonce, ServiceNonce)

	c := initialiseClient(5 * time.Second)
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
	ServiceNonce = val.Nonce
	dashLog.Info("De-registered.")

	return nil
}
