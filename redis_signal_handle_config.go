package main

import (
	"encoding/json"
	"io/ioutil"
	"syscall"
	"time"

	"github.com/TykTechnologies/logrus"
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

	filename := "./tyk.conf"
	if conf := argumentsBackup["--conf"]; conf != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Infof("Using %s for configuration", conf.(string))
		filename = conf.(string)
	} else {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("No configuration file defined, will try to use default (./tyk.conf)")
	}

	ioutil.WriteFile(filename, newConfig, 0644)
	return nil
}

func GetExistingRawConfig() Config {
	filename := "./tyk.conf"
	if conf := argumentsBackup["--conf"]; conf != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Infof("Using %s for configuration", conf.(string))
		filename = conf.(string)
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
	configPayload := ConfigPayload{}

	// We actually want to merge into the existing configuration
	// so as not to lose data through automatic defaults
	configPayload.Configuration = GetExistingRawConfig()

	err := json.Unmarshal([]byte(payload), &configPayload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to decode configuration payload: ", err)
		return
	}

	// Make sure payload matches nodeID and hostname
	if configPayload.ForHostname != HostDetails.Hostname && configPayload.ForNodeID != NodeID {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("Configuration update received, no NodeID/Hostname match found")
		return
	}

	if config.AllowRemoteConfig {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Warning("Ignoring new config: Remote configuration is not allowed for this node.")
		return
	}

	if err := BackupConfiguration(); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to backup existing configuration: ", err)
		return
	}

	if err := WriteNewConfiguration(configPayload); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to write new configuration: ", err)
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "pub-sub",
	}).Info("Initiating configuration reload")

	ReloadConfiguration()
}

func ReloadConfiguration() {
	myPID := HostDetails.PID
	if myPID == 0 {
		log.Error("No PID found, cannot reload")
		return
	}

	log.Info("Sending reload signal to PID: ", myPID)
	if err := syscall.Kill(myPID, syscall.SIGUSR2); err != nil {
		log.Error("Process reload failed: ", err)
	}
}
