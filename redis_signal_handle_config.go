package main

import (
	"encoding/json"
	"fmt"
	"github.com/TykTechnologies/logrus"
	"io/ioutil"
	"time"
)

type ConfigPayload struct {
	Configuration Config
	ForHostname   string
	ForNodeID     string
	TimeStamp     int64
}

func BackupConfiguration() error {
	oldConfig, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}

	now := time.Now()
	asStr := now.Format("Mon-Jan-_2-15-04-05-2006")
	fName := asStr + ".tyk.conf"
	ioutil.WriteFile(fName, oldConfig, 0644)
	return nil
}

func WriteNewConfiguration(payload ConfigPayload) error {
	newConfig, err := json.MarshalIndent(payload.Configuration, "", "    ")
	if err != nil {
		return err
	}

	value, _ := argumentsBackup["--conf"]
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

	ioutil.WriteFile(filename, newConfig, 0644)
	return nil
}

func GetExistingRawConfig() Config {
	value, _ := argumentsBackup["--conf"]
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

	existingConfig := Config{}
	loadConfig(filename, &existingConfig)

	return existingConfig
}

func HandleNewConfiguration(payload string) {
	// Decode the configuration from the payload
	thisConfigPayload := ConfigPayload{}

	// We actually want to merge into the existing configuration
	// so as not to lose data through automatic defaults
	thisConfigPayload.Configuration = GetExistingRawConfig()

	err := json.Unmarshal([]byte(payload), &thisConfigPayload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to decode configuration payload: ", err)
		return
	}

	// Make sure payload matches nodeID and hostname
	if (thisConfigPayload.ForHostname != HostDetails.Hostname) && (thisConfigPayload.ForNodeID != NodeID) {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("Configuration update received, no NodeID/Hostname match found")
		return
	}

	if !config.AllowRemoteConfig == false {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Warning("Ignoring new config: Remote configuration is not allowed for this node.")
		return
	}

	backupErr := BackupConfiguration()
	if backupErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to backup existing configuration: ", backupErr)
		return
	}

	writeErr := WriteNewConfiguration(thisConfigPayload)
	if writeErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to write new configuration: ", writeErr)
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "pub-sub",
	}).Info("Initiating configuration reload")

	ReloadConfiguration()
}
