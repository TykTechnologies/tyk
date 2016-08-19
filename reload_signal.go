package main

import (
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/garyburd/redigo/redis"
	"io/ioutil"
	"time"
)

const (
	RedisPubSubChannel string = "tyk.cluster.notifications"
)

func StartPubSubLoop() {
	CacheStore := RedisClusterStorageManager{}
	CacheStore.Connect()
	// On message, synchronise
	for {
		err := CacheStore.StartPubSubHandler(RedisPubSubChannel, HandleRedisMsg)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
				"err":    err,
			}).Error("Connection to Redis failed, reconnect in 10s")

			time.Sleep(10 * time.Second)
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
			}).Warning("Reconnecting")

			CacheStore.Connect()
			CacheStore.StartPubSubHandler(RedisPubSubChannel, HandleRedisMsg)
		}

	}
}

func HandleRedisMsg(message redis.Message) {
	thisMessage := Notification{}
	err := json.Unmarshal(message.Data, &thisMessage)
	if err != nil {
		log.Error("Unmarshalling message body failed, malformed: ", err)
		return
	}

	if thisMessage.Command == NoticeConfigUpdate {
		HandleNewConfiguration(thisMessage.Payload)
	} else {
		HandleReloadMsg()
	}
}

func IsConfigSignatureValid(payload ConfigPayload) bool {
	if payload.Signature == "" && config.AllowInsecureConfigs {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Warning("Insecure configuration detected!")
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Warning("--> Allowing (to block please update allow_insecure_configs)")
		return true
	}

	return false
}

type ConfigPayload struct {
	Configuration Config
	Signature     string
	ForHostname   string
	ForNodeID     string
	TimeStamp     string
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

func HandleNewConfiguration(payload string) {
	// Decode the configuration from the payload
	thisConfigPayload := ConfigPayload{}
	err := json.Unmarshal([]byte(payload), &thisConfigPayload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to decode configuration payload")
		return
	}

	// Make sure payload matches nodeID and hostname
	if (thisConfigPayload.ForHostname != HostDetails.Hostname) && (thisConfigPayload.ForNodeID != NodeID) {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("Configuration update received, no NodeID/Hostname match found")
		return
	}

	// Then:
	if !IsConfigSignatureValid(thisConfigPayload) {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Configuration update signature is invalid!")
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

func HandleReloadMsg() {
	log.WithFields(logrus.Fields{
		"prefix": "pub-sub",
	}).Info("Reloading endpoints")
	ReloadURLStructure()
}
