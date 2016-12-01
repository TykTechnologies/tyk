package main

import (
	"encoding/json"
	"fmt"
	"github.com/TykTechnologies/logrus"
	"io/ioutil"
	"time"
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
	thisMicroConfig := MicroConfig{}

	var filename string = "./tyk.conf"
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
		return thisMicroConfig, err
	}

	jsErr := json.Unmarshal(dat, &thisMicroConfig)
	if jsErr != nil {
		return thisMicroConfig, jsErr
	}

	thisMicroConfig = SanitizeConfig(thisMicroConfig)

	return thisMicroConfig, nil
}

func HandleSendMiniConfig(payload string) {
	// Decode the configuration from the payload
	thisConfigPayload := GetConfigPayload{}
	jsErr := json.Unmarshal([]byte(payload), &thisConfigPayload)
	if jsErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed unmarshal request: ", jsErr)
		return
	}

	// Make sure payload matches nodeID and hostname
	if (thisConfigPayload.FromHostname != HostDetails.Hostname) && (thisConfigPayload.FromNodeID != NodeID) {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("Configuration request received, no NodeID/Hostname match found, ignoring")
		return
	}

	thisConfig, getConfErr := GetExistingConfig()
	if getConfErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to get existing configuration: ", getConfErr)
		return
	}

	returnPayload := ReturnConfigPayload{
		FromHostname:  HostDetails.Hostname,
		FromNodeID:    NodeID,
		Configuration: thisConfig,
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
	}).Info("Configuration request responded.")

}
