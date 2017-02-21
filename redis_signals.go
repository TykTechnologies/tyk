package main

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/garyburd/redigo/redis"

	"github.com/TykTechnologies/goverify"
	"github.com/TykTechnologies/logrus"
)

const (
	RedisPubSubChannel = "tyk.cluster.notifications"
)

func StartPubSubLoop() {
	CacheStore := RedisClusterStorageManager{}
	CacheStore.Connect()
	// On message, synchronise
	for {
		err := CacheStore.StartPubSubHandler(RedisPubSubChannel, HandleRedisEvent)
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
			CacheStore.StartPubSubHandler(RedisPubSubChannel, HandleRedisEvent)
		}

	}
}

func HandleRedisEvent(v interface{}) {
	message, ok := v.(redis.Message)
	if !ok {
		return
	}
	notif := Notification{}
	if err := json.Unmarshal(message.Data, &notif); err != nil {
		log.Error("Unmarshalling message body failed, malformed: ", err)
		return
	}

	// Add messages to ignore here
	ignoreMessageList := map[NotificationCommand]bool{
		NoticeGatewayConfigResponse: true,
	}

	// Don't react to all messages
	_, ignore := ignoreMessageList[notif.Command]
	if ignore {
		return
	}

	// Check for a signature, if not signature found, handle
	if !IsPayloadSignatureValid(notif) {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Payload signature is invalid!")
		return
	}

	switch notif.Command {
	case NoticeDashboardZeroConf:
		HandleDashboardZeroConfMessage(notif.Payload)
		break
	case NoticeConfigUpdate:
		HandleNewConfiguration(notif.Payload)
		break
	case NoticeDashboardConfigRequest:
		HandleSendMiniConfig(notif.Payload)
	case NoticeGatewayDRLNotification:
		OnServerStatusReceivedHandler(notif.Payload)
	case NoticeGatewayLENotification:
		OnLESSLStatusReceivedHandler(notif.Payload)
	default:
		HandleReloadMsg()
		break
	}

}

func HandleReloadMsg() {
	log.WithFields(logrus.Fields{
		"prefix": "pub-sub",
	}).Info("Reloading endpoints")
	ReloadURLStructure(nil)
}

var warnedOnce bool
var notificationVerifier goverify.Verifier

func IsPayloadSignatureValid(notification Notification) bool {
	switch notification.Command {
	case NoticeGatewayDRLNotification, NoticeGatewayLENotification:
		// Gateway to gateway
		return true
	}

	if notification.Signature == "" && config.AllowInsecureConfigs {
		if !warnedOnce {
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
			}).Warning("Insecure configuration detected (allowing)!")
			warnedOnce = true
		}
		return true
	}

	if config.PublicKeyPath != "" {
		if notificationVerifier == nil {
			var err error
			notificationVerifier, err = goverify.LoadPublicKeyFromFile(config.PublicKeyPath)
			if err != nil {
				log.WithFields(logrus.Fields{
					"prefix": "pub-sub",
				}).Error("Notification signer: Failed loading private key from path: ", err)
				return false
			}
		}
	}

	if notificationVerifier != nil {
		signed, err := base64.StdEncoding.DecodeString(notification.Signature)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
			}).Error("Failed to decode signature: ", err)
			return false
		}
		if err := notificationVerifier.Verify([]byte(notification.Payload), signed); err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
			}).Error("Could not verify notification: ", err, ": ", notification)

			return false
		}

		return true
	}

	return false
}
