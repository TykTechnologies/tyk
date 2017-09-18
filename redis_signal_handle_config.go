package main

import (
	"encoding/json"
	"io/ioutil"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
)

type ConfigPayload struct {
	Configuration config.Config
	ForHostname   string
	ForNodeID     string
	TimeStamp     int64
}

func backupConfiguration() error {
	oldConfig, err := json.MarshalIndent(config.Global, "", "    ")
	if err != nil {
		return err
	}

	now := time.Now()
	asStr := now.Format("Mon-Jan-_2-15-04-05-2006")
	fName := asStr + ".tyk.conf"
	ioutil.WriteFile(fName, oldConfig, 0644)
	return nil
}

func writeNewConfiguration(payload ConfigPayload) error {
	newConfig, err := json.MarshalIndent(payload.Configuration, "", "    ")
	if err != nil {
		return err
	}

	ioutil.WriteFile(confPaths[0], newConfig, 0644)
	return nil
}

func getExistingRawConfig() config.Config {
	existingConfig := config.Config{}
	config.Load(confPaths, &existingConfig)
	return existingConfig
}

func handleNewConfiguration(payload string) {
	// Decode the configuration from the payload
	configPayload := ConfigPayload{}

	// We actually want to merge into the existing configuration
	// so as not to lose data through automatic defaults
	configPayload.Configuration = getExistingRawConfig()

	err := json.Unmarshal([]byte(payload), &configPayload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to decode configuration payload: ", err)
		return
	}

	// Make sure payload matches nodeID and hostname
	if configPayload.ForHostname != hostDetails.Hostname && configPayload.ForNodeID != NodeID {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("Configuration update received, no NodeID/Hostname match found")
		return
	}

	if config.Global.AllowRemoteConfig {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Warning("Ignoring new config: Remote configuration is not allowed for this node.")
		return
	}

	if err := backupConfiguration(); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to backup existing configuration: ", err)
		return
	}

	if err := writeNewConfiguration(configPayload); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to write new configuration: ", err)
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "pub-sub",
	}).Info("Initiating configuration reload")

	reloadConfiguration()
}

func reloadConfiguration() {
	myPID := hostDetails.PID
	if myPID == 0 {
		log.Error("No PID found, cannot reload")
		return
	}

	log.Info("Sending reload signal to PID: ", myPID)
	if err := syscall.Kill(myPID, syscall.SIGUSR2); err != nil {
		log.Error("Process reload failed: ", err)
	}
}
