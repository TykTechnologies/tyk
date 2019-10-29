package dashboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/headers"
)

type NodeResponseOK struct {
	Status  string
	Message map[string]string
	Nonce   string
}

type TaggedApis struct {
	Message []struct {
		ApiDefinition *apidef.APIDefinition `bson:"api_definition" json:"api_definition"`
	}
	Nonce string
}

type (
	NonceSetCallback     func(nonce string)
	NonceGetCallback     func() string
	NodeIdUpdateCallback func(id string)
)

type HTTPDashboardHandler struct {
	Secret                string
	Hostname              string
	NodeId                string
	BaseConnectionPath    string
	heartBeatStopSentinel bool

	RegistrationEndpoint    string
	DeRegistrationEndpoint  string
	HeartBeatEndpoint       string
	KeyQuotaTriggerEndpoint string
	ApisEndpoint            string

	client *http.Client
	log    *logrus.Entry

	nonceGet     NonceGetCallback
	nonceSet     NonceSetCallback
	nodeCallback NodeIdUpdateCallback
}

func NewHandler(client *http.Client, log *logrus.Entry, hostname, nodeID, secret, connectionStr string,
	nonceGet NonceGetCallback, nonceSet NonceSetCallback, nodeCallback NodeIdUpdateCallback) *HTTPDashboardHandler {

	h := &HTTPDashboardHandler{
		client:             client,
		log:                log,
		Hostname:           hostname,
		NodeId:             nodeID,
		Secret:             secret,
		BaseConnectionPath: connectionStr,
		nonceGet:           nonceGet,
		nonceSet:           nonceSet,
		nodeCallback:       nodeCallback,
	}
	h.init()

	return h
}

func (h *HTTPDashboardHandler) init() {
	h.RegistrationEndpoint = h.buildEndpointPath("register/node")
	h.DeRegistrationEndpoint = h.buildEndpointPath("system/node")
	h.HeartBeatEndpoint = h.buildEndpointPath("register/ping")
	h.KeyQuotaTriggerEndpoint = h.buildEndpointPath("system/key/quota_trigger")
	h.ApisEndpoint = h.buildEndpointPath("system/apis")
}

// NotifyDashboardOfEvent acts as a form of event which informs the
// dashboard of a key which has reached a certain usage quota
func (h *HTTPDashboardHandler) NotifyDashboardOfEvent(event interface{}) error {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(event); err != nil {
		h.log.Errorf("Could not decode event metadata :%v", err)
		return err
	}

	req, err := http.NewRequest(http.MethodPost, h.KeyQuotaTriggerEndpoint, &b)
	if err != nil {
		h.log.Errorf("Could not create request.. %v", err)
		return err
	}

	req.Header.Set("authorization", h.Secret)
	req.Header.Set(headers.XTykNodeID, h.NodeId)
	req.Header.Set(headers.XTykNonce, h.nonceGet())

	resp, err := h.client.Do(req)
	if err != nil {
		h.log.Errorf("Request failed with error %v", err)
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("Unexpected status code while trying to notify dashboard of a key limit quota trigger.. Got %d", resp.StatusCode)
		h.log.Error(err)
		return err
	}

	val := NodeResponseOK{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		return err
	}

	h.nonceSet(val.Nonce)

	return nil
}

func (h *HTTPDashboardHandler) Register() error {
	h.log.Info("Registering gateway node with Dashboard")
	req := h.newRequest(h.RegistrationEndpoint)

	resp, err := h.client.Do(req)
	if err != nil {
		h.log.Errorf("Request failed with error %v; retrying in 5s", err)
		time.Sleep(time.Second * 5)
		return h.Register()
	} else if resp != nil && resp.StatusCode != 200 {
		h.log.Errorf("Response failed with code %d; retrying in 5s", resp.StatusCode)
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
	h.nodeCallback(nodeID)
	h.NodeId = nodeID
	if !found {
		h.log.Error("Failed to register node, retrying in 5s")
		time.Sleep(time.Second * 5)
		return h.Register()
	}

	h.log.WithField("id", h.NodeId).Info("Node Registered")

	// Set the nonce
	h.nonceSet(val.Nonce)
	h.log.Debug("Registration Finished: Nonce Set: ", val.Nonce)

	return nil
}

func (h *HTTPDashboardHandler) StartBeating() {
	req := h.newRequest(h.HeartBeatEndpoint)

	for !h.heartBeatStopSentinel {
		if err := h.sendHeartBeat(req); err != nil {
			h.log.Warning(err)
		}
		time.Sleep(time.Second * 2)
	}

	h.log.Info("Stopped Heartbeat")
	h.heartBeatStopSentinel = false
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
	req.Header.Set(headers.XTykHostname, h.Hostname)
	return req
}

func (h *HTTPDashboardHandler) sendHeartBeat(req *http.Request) error {
	req.Header.Set(headers.XTykNodeID, h.NodeId)
	req.Header.Set(headers.XTykNonce, h.nonceGet())

	resp, err := h.client.Do(req)
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
	h.nonceSet(val.Nonce)

	return nil
}

func (h *HTTPDashboardHandler) DeRegister() error {
	req := h.newRequest(h.DeRegistrationEndpoint)

	req.Header.Set(headers.XTykNodeID, h.NodeId)
	req.Header.Set(headers.XTykNonce, h.nonceGet())

	resp, err := h.client.Do(req)

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

	h.nonceSet(val.Nonce)
	h.log.Info("De-registered.")

	return nil
}

func (h *HTTPDashboardHandler) FetchApiSpecs(nonce string) (*TaggedApis, error) {
	h.log.Debug("Calling: ", h.ApisEndpoint)
	newRequest, err := http.NewRequest("GET", h.ApisEndpoint, nil)
	if err != nil {
		h.log.Error("Failed to create request: ", err)
	}

	newRequest.Header.Set("authorization", h.Secret)
	h.log.Debug("Using: NodeID: ", h.NodeId)
	newRequest.Header.Set(headers.XTykNodeID, h.NodeId)

	newRequest.Header.Set(headers.XTykNonce, nonce)

	resp, err := h.client.Do(newRequest)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("login failure, Response was: %v", string(body))
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("dashboard API error, response was: %v", string(body))
	}

	var list TaggedApis
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode body: %v body was: %v", err, string(body))
	}

	return &list, nil
}

func (h HTTPDashboardHandler) buildEndpointPath(endpoint string) string {
	return fmt.Sprintf("%s/%s", h.BaseConnectionPath, endpoint)
}
