package main

import (
	"encoding/json"
	"github.com/Sirupsen/logrus"
	"github.com/garyburd/redigo/redis"
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

	// Check for a signature, if not signature found, handle
	if !IsPayloadSignatureValid(thisMessage) {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Payload signature is invalid!")
		return
	}

	switch thisMessage.Command {
	case NoticeDashboardZeroConf:
		HandleDashboardZeroConfMessage(thisMessage.Payload)
		break
	case NoticeConfigUpdate:
		HandleNewConfiguration(thisMessage.Payload)
		break
	default:
		HandleReloadMsg()
		break
	}

}

var warnedOnce bool

func IsPayloadSignatureValid(notification Notification) bool {
	if notification.Signature == "" && config.AllowInsecureConfigs {
		if warnedOnce == false {
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
			}).Warning("Insecure configuration detected (allowing)!")	
			warnedOnce = true
		}
		
		return true
	}

	return false
}
