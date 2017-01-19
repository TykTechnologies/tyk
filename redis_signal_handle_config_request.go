package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/TykTechnologies/logrus"
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

func SanitizeConfig(mc MicroConfig) MicroConfig {

	SanitzeFields := []string{
		"secret",
		"node_secret",
		"storage",
		"slave_options",
		"auth_override",
	}

	for _, field_name := range SanitzeFields {
		delete(mc, field_name)
	}

	return mc
}

func GetExistingConfig() (MicroConfig, error) {
	value, _ := argumentsBackup["--conf"]
	microConfig := MicroConfig{}

	filename := "./tyk.conf"
	if value != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info(fmt.Sprintf("Using %s for configuration", value.(string)))
		filename = argumentsBackup["--conf"].(string)
	} else {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("No configuration file defined, will try to use default (./tyk.conf)")
	}

	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		return microConfig, err
	}
	if err := json.Unmarshal(dat, &microConfig); err != nil {
		return microConfig, err
	}
	return SanitizeConfig(microConfig), nil
}

func HandleSendMiniConfig(payload string) {
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
	if (configPayload.FromHostname != HostDetails.Hostname) && (configPayload.FromNodeID != NodeID) {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Debug("Configuration request received, no NodeID/Hostname match found, ignoring")
		return
	}

	config, err := GetExistingConfig()
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

	payloadAsJSON, jsmErr := json.Marshal(returnPayload)
	if jsmErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to get marshal configuration: ", jsmErr)
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
