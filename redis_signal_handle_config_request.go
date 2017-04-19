package main

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/Sirupsen/logrus"
)

type GetConfigPayload struct {
	FromHostname string
	FromNodeID   string
	TimeStamp    int64
}

type ReturnConfigPayload struct {
	FromHostname  string
	FromNodeID    string
	Configuration MicroConfig
	TimeStamp     int64
}

type MicroConfig map[string]interface{}

func sanitizeConfig(mc MicroConfig) MicroConfig {

	sanitzeFields := []string{
		"secret",
		"node_secret",
		"storage",
		"slave_options",
		"auth_override",
	}

	for _, field_name := range sanitzeFields {
		delete(mc, field_name)
	}

	return mc
}

func getExistingConfig() (MicroConfig, error) {
	microConfig := MicroConfig{}
	dat, err := ioutil.ReadFile(usedConfPath)
	if err != nil {
		return microConfig, err
	}
	if err := json.Unmarshal(dat, &microConfig); err != nil {
		return microConfig, err
	}
	return sanitizeConfig(microConfig), nil
}

func handleSendMiniConfig(payload string) {
	// Decode the configuration from the payload
	configPayload := GetConfigPayload{}
	err := json.Unmarshal([]byte(payload), &configPayload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed unmarshal request: ", err)
		return
	}

	// Make sure payload matches nodeID and hostname
	if configPayload.FromHostname != HostDetails.Hostname && configPayload.FromNodeID != NodeID {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Debug("Configuration request received, no NodeID/Hostname match found, ignoring")
		return
	}

	config, err := getExistingConfig()
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to get existing configuration: ", err)
		return
	}

	returnPayload := ReturnConfigPayload{
		FromHostname:  HostDetails.Hostname,
		FromNodeID:    NodeID,
		Configuration: config,
		TimeStamp:     time.Now().Unix(),
	}

	payloadAsJSON, err := json.Marshal(returnPayload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to get marshal configuration: ", err)
		return
	}

	asNotification := Notification{
		Command: NoticeGatewayConfigResponse,
		Payload: string(payloadAsJSON),
	}

	MainNotifier.Notify(asNotification)
	log.WithFields(logrus.Fields{
		"prefix": "pub-sub",
	}).Debug("Configuration request responded.")

}
