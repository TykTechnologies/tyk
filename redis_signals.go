package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/goverify"
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

	// Add messages to ignore here
	ignoreMessageList := map[NotificationCommand]bool{
		NoticeGatewayConfigResponse: true,
	}

	// Don't react to all messages
	_, ignore := ignoreMessageList[thisMessage.Command]
	if ignore {
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
	case NoticeDashboardConfigRequest:
		HandleSendMiniConfig(thisMessage.Payload)
	case NoticeGatewayDRLNotification:
		OnServerStatusReceivedHandler(thisMessage.Payload)
	case NoticeGatewayLENotification:
		OnLESSLStatusReceivedHandler(thisMessage.Payload)
	default:
		HandleReloadMsg()
		break
	}

}

var warnedOnce bool
var notificationVerifier goverify.Verifier

func IsPayloadSignatureValid(notification Notification) bool {
	if (notification.Command == NoticeGatewayDRLNotification) || (notification.Command == NoticeGatewayLENotification) {
		// Gateway to gateway
		return true
	}

	if notification.Signature == "" && config.AllowInsecureConfigs {
		if warnedOnce == false {
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
			}).Warning("Insecure configuration detected (allowing)!")
			warnedOnce = true
		}

		return true
	}

	if config.PublicKeyPath != "" {
		if notificationVerifier == nil {
			var loadErr error
			notificationVerifier, loadErr = goverify.LoadPublicKeyFromFile(config.PublicKeyPath)
			if loadErr != nil {
				log.WithFields(logrus.Fields{
					"prefix": "pub-sub",
				}).Error("Notification signer: Failed loading private key from path: ", loadErr)
				return false
			}
		}
	}

	if notificationVerifier != nil {
		signed, decErr := b64.StdEncoding.DecodeString(notification.Signature)
		if decErr != nil {
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
			}).Error("Failed to decode signature: ", decErr)
			return false
		}
		err := notificationVerifier.Verify([]byte(notification.Payload), signed)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
			}).Error("Could not verify notification: ", err, ": ", notification)
			
			return false
		}

		return true
	}

	return false
}
