package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Sirupsen/logrus"
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

func reLogin() {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Registering node (again).")
	DashService.StopBeating()
	DashService.DeRegister()

	time.Sleep(30 * time.Second)

	if err := DashService.Register(); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error(err)
	} else {
		go DashService.StartBeating()
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Recovering configurations, reloading...")
	doReload()
}

func (h *HTTPDashboardHandler) Init() error {
	h.RegistrationEndpoint = buildConnStr("/register/node")
	h.DeRegistrationEndpoint = buildConnStr("/system/node")
	h.HeartBeatEndpoint = buildConnStr("/register/ping")

	h.Secret = config.NodeSecret
	return nil
}

func (h *HTTPDashboardHandler) Register() error {
	// Get the definitions

	endpoint := h.RegistrationEndpoint
	secret := h.Secret

	log.Debug("Calling: ", endpoint)
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
	}

	newRequest.Header.Add("authorization", secret)
	newRequest.Header.Add("x-tyk-hostname", HostDetails.Hostname)

	c := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := c.Do(newRequest)
	if err != nil {
		log.Error("Request failed: ", err)
		time.Sleep(time.Second * 5)
		return h.Register()
	}
	if resp.StatusCode != 200 {
		log.Error("Failed to register node, retrying in 5s")
		time.Sleep(time.Second * 5)
		return h.Register()
	}

	defer resp.Body.Close()
	val := NodeResponseOK{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		log.Error("Failed to decode body: ", err)
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
	for !h.heartBeatStopSentinel {
		failure := h.SendHeartBeat(h.HeartBeatEndpoint, h.Secret)
		if failure != nil {
			log.Warning(failure)
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

func (h *HTTPDashboardHandler) SendHeartBeat(endpoint, secret string) error {
	// Get the definitions
	log.Debug("Calling: ", endpoint)
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
	}

	newRequest.Header.Add("authorization", secret)
	newRequest.Header.Add("x-tyk-nodeid", NodeID)
	newRequest.Header.Add("x-tyk-hostname", HostDetails.Hostname)

	log.Debug("Sending Heartbeat as: ", NodeID)

	newRequest.Header.Add("x-tyk-nonce", ServiceNonce)

	c := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := c.Do(newRequest)
	if err != nil || resp.StatusCode != 200 {
		return errors.New("dashboard is down? Heartbeat is failing")
	}

	defer resp.Body.Close()
	val := NodeResponseOK{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		log.Error("Failed to decode body: ", err)
		return err
	}

	// Set the nonce
	ServiceNonce = val.Nonce
	log.Debug("Heartbeat Finished: Nonce Set: ", ServiceNonce)

	return nil
}

func (h *HTTPDashboardHandler) DeRegister() error {
	// Get the definitions

	endpoint := h.DeRegistrationEndpoint
	secret := h.Secret

	log.Debug("Calling: ", endpoint)
	newRequest, err := http.NewRequest("DELETE", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
	}

	newRequest.Header.Add("authorization", secret)
	newRequest.Header.Add("x-tyk-nodeid", NodeID)
	newRequest.Header.Add("x-tyk-hostname", HostDetails.Hostname)

	log.Info("De-registering: ", NodeID)

	newRequest.Header.Add("x-tyk-nonce", ServiceNonce)

	c := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := c.Do(newRequest)
	if err != nil {
		log.Error("Dashboard is down? Failed fo de-register: ", err)
		return err
	}

	if resp.StatusCode != 200 {
		log.Error("Dashboard is down? Failed fo de-register, incorrect status: ", resp.StatusCode)
		return errors.New("Incorrect status code")
	}

	defer resp.Body.Close()
	val := NodeResponseOK{}
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		log.Error("Failed to decode body: ", err)
		return err
	}

	// Set the nonce
	ServiceNonce = val.Nonce
	log.Info("De-registered.")

	return nil
}
