package main

import (
	"encoding/json"
	"errors"
	"github.com/Sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"time"
)

type NodeResponseOK struct {
	Status  string
	Message map[string]string
	Nonce   string
}

type DashboardServiceSender interface {
	Init() error
	Register() error
	StartBeating() error
	StopBeating()
}

type HTTPDashboardHandler struct {
	RegistrationEndpoint string
	HeartBeatEndpoint    string
	Secret               string

	heartBeatStopSentinel bool
}

func ReLogin() {
	// connStr := config.DBAppConfOptions.ConnectionString
	// if connStr == "" {
	// 	log.Fatal("Connection string is empty, failing.")
	// }

	// connStr := connStr + "/register/node"
	// log.WithFields(logrus.Fields{
	// 	"prefix": "main",
	// }).Info("Registering node (again).")
	
	err := DashService.Register()
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error(err)
	}
}

func (h *HTTPDashboardHandler) Init() error {
	h.RegistrationEndpoint = buildConnStr("/register/node")
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

	c := &http.Client{}
	response, reqErr := c.Do(newRequest)

	if reqErr != nil {
		log.Error("Request failed: ", reqErr)
		time.Sleep(time.Second * 5)
		return h.Register()
	}

	defer response.Body.Close()
	retBody, err := ioutil.ReadAll(response.Body)

	if response.StatusCode != 200 {
		log.Error("Failed to register node, retrying in 5s")
		log.Debug("Response was: ", string(retBody))
		time.Sleep(time.Second * 5)
		return h.Register()
	}

	if err != nil {
		return err
	}

	thisVal := NodeResponseOK{}
	decErr := json.Unmarshal(retBody, &thisVal)
	if decErr != nil {
		log.Error("Failed to decode body: ", decErr)
		return decErr
	}

	// Set the NodeID
	var found bool
	NodeID, found = thisVal.Message["NodeID"]
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
	ServiceNonceMutex.Lock()
	ServiceNonce = thisVal.Nonce
	log.Debug("Registration Finished: Nonce Set: ", ServiceNonce)
	ServiceNonceMutex.Unlock()

	return nil
}

func (h *HTTPDashboardHandler) StartBeating() error {
	for {
		if h.heartBeatStopSentinel == true {
			break
		}
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

func (h *HTTPDashboardHandler) SendHeartBeat(endpoint string, secret string) error {
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

	ServiceNonceMutex.Lock()
	newRequest.Header.Add("x-tyk-nonce", ServiceNonce)

	c := &http.Client{}
	response, reqErr := c.Do(newRequest)

	if reqErr != nil {
		return errors.New("Dashboard is down? Heartbeat is failing.")
	}

	if response.StatusCode != 200 {
		return errors.New("Dashboard is down? Heartbeat is failing.")
	}

	defer response.Body.Close()
	retBody, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return err
	}

	thisVal := NodeResponseOK{}
	decErr := json.Unmarshal(retBody, &thisVal)
	if decErr != nil {
		log.Error("Failed to decode body: ", decErr)
		return decErr
	}

	// Set the nonce
	ServiceNonce = thisVal.Nonce
	log.Debug("Hearbeat Finished: Nonce Set: ", ServiceNonce)
	ServiceNonceMutex.Unlock()

	return nil
}
