package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
)

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
}

type HTTPDashboardHandler struct {
	RegistrationEndpoint   string
	DeRegistrationEndpoint string
	HeartBeatEndpoint      string
	Secret                 string

	heartBeatStopSentinel bool
}

func initialiseClient(timeout time.Duration) *http.Client {
	client := &http.Client{}
	if config.Global().HttpServerOptions.UseSSL {
		// Setup HTTPS client
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.Global().HttpServerOptions.SSLInsecureSkipVerify,
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client = &http.Client{Transport: transport, Timeout: timeout}
	} else {
		client = &http.Client{Timeout: timeout}
	}
	return client
}

func reLogin() {
	if !config.Global().UseDBAppConfigs {
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Registering node (again).")
	DashService.StopBeating()
	if err := DashService.DeRegister(); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("Could not deregister: ", err)
	}

	time.Sleep(5 * time.Second)

	if err := DashService.Register(); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("Could not register: ", err)
	} else {
		go DashService.StartBeating()
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Recovering configurations, reloading...")
	reloadURLStructure(nil)
}

func (h *HTTPDashboardHandler) Init() error {
	h.RegistrationEndpoint = buildConnStr("/register/node")
	h.DeRegistrationEndpoint = buildConnStr("/system/node")
	h.HeartBeatEndpoint = buildConnStr("/register/ping")
	if h.Secret = config.Global().NodeSecret; h.Secret == "" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Fatal("Node secret is not set, required for dashboard connection")
	}
	return nil
}

func (h *HTTPDashboardHandler) Register() error {
	req := h.newRequest(h.RegistrationEndpoint)
	c := initialiseClient(5 * time.Second)
	resp, err := c.Do(req)

	if err != nil {
		log.Errorf("Request failed with error %v; retrying in 5s", err)
		time.Sleep(time.Second * 5)
		return h.Register()
	} else if resp != nil && resp.StatusCode != 200 {
		log.Errorf("Response failed with code %d; retrying in 5s", resp.StatusCode)
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
	NodeID, found = val.Message["NodeID"]
	if !found {
		log.Error("Failed to register node, retrying in 5s")
		time.Sleep(time.Second * 5)
		return h.Register()
	}

	log.WithFields(logrus.Fields{
		"prefix": "dashboard",
		"id":     NodeID,
	}).Info("Node registered")

	// Set the nonce
	ServiceNonce = val.Nonce
	log.Debug("Registration Finished: Nonce Set: ", ServiceNonce)

	return nil
}

func (h *HTTPDashboardHandler) StartBeating() error {

	req := h.newRequest(h.HeartBeatEndpoint)

	client := initialiseClient(5 * time.Second)

	for !h.heartBeatStopSentinel {
		if err := h.sendHeartBeat(req, client); err != nil {
			log.Warning(err)
		}
		time.Sleep(time.Second * 2)
	}

	log.Info("Stopped Heartbeat")
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
	req.Header.Set("x-tyk-hostname", hostDetails.Hostname)
	return req
}

func (h *HTTPDashboardHandler) sendHeartBeat(req *http.Request, client *http.Client) error {
	req.Header.Set("x-tyk-nodeid", NodeID)
	req.Header.Set("x-tyk-nonce", ServiceNonce)
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

	req.Header.Set("x-tyk-nodeid", NodeID)
	req.Header.Set("x-tyk-nonce", ServiceNonce)

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
	log.Info("De-registered.")

	return nil
}
