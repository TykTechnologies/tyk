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

func startPubSubLoop() {
	cacheStore := RedisClusterStorageManager{}
	cacheStore.Connect()
	// On message, synchronise
	for {
		err := cacheStore.StartPubSubHandler(RedisPubSubChannel, handleRedisEvent)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
				"err":    err,
			}).Error("Connection to Redis failed, reconnect in 10s")

			time.Sleep(10 * time.Second)
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
			}).Warning("Reconnecting")
		}

	}
}

func handleRedisEvent(v interface{}) {
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
	switch notif.Command {
	case NoticeGatewayConfigResponse:
		return
	}

	// Check for a signature, if not signature found, handle
	if !isPayloadSignatureValid(notif) {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Payload signature is invalid!")
		return
	}

	switch notif.Command {
	case NoticeDashboardZeroConf:
		HandleDashboardZeroConfMessage(notif.Payload)
	case NoticeConfigUpdate:
		HandleNewConfiguration(notif.Payload)
	case NoticeDashboardConfigRequest:
		HandleSendMiniConfig(notif.Payload)
	case NoticeGatewayDRLNotification:
		OnServerStatusReceivedHandler(notif.Payload)
	case NoticeGatewayLENotification:
		OnLESSLStatusReceivedHandler(notif.Payload)
	case NoticeGroupReload:
		handleReloadMsg()
	default:
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Warnf("Unknown notification command: %q", notif.Command)
	}

}

func handleReloadMsg() {
	log.WithFields(logrus.Fields{
		"prefix": "pub-sub",
	}).Info("Reloading endpoints")
	reloadURLStructure(nil)
}

var warnedOnce bool
var notificationVerifier goverify.Verifier

func isPayloadSignatureValid(notification Notification) bool {
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
