package main

import (
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/garyburd/redigo/redis"

	"github.com/TykTechnologies/goverify"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

type NotificationCommand string

const (
	RedisPubSubChannel = "tyk.cluster.notifications"

	NoticeApiUpdated             NotificationCommand = "ApiUpdated"
	NoticeApiRemoved             NotificationCommand = "ApiRemoved"
	NoticeApiAdded               NotificationCommand = "ApiAdded"
	NoticeGroupReload            NotificationCommand = "GroupReload"
	NoticePolicyChanged          NotificationCommand = "PolicyChanged"
	NoticeConfigUpdate           NotificationCommand = "NoticeConfigUpdated"
	NoticeDashboardZeroConf      NotificationCommand = "NoticeDashboardZeroConf"
	NoticeDashboardConfigRequest NotificationCommand = "NoticeDashboardConfigRequest"
	NoticeGatewayConfigResponse  NotificationCommand = "NoticeGatewayConfigResponse"
	NoticeGatewayDRLNotification NotificationCommand = "NoticeGatewayDRLNotification"
	NoticeGatewayLENotification  NotificationCommand = "NoticeGatewayLENotification"
)

// Notification is a type that encodes a message published to a pub sub channel (shared between implementations)
type Notification struct {
	Command   NotificationCommand `json:"command"`
	Payload   string              `json:"payload"`
	Signature string              `json:"signature"`
}

func startPubSubLoop() {
	cacheStore := storage.RedisCluster{}
	cacheStore.Connect()
	// On message, synchronise
	for {
		err := cacheStore.StartPubSubHandler(RedisPubSubChannel, func(v interface{}) {
			handleRedisEvent(v, nil, nil)
		})
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

func handleRedisEvent(v interface{}, handled func(NotificationCommand), reloaded func()) {
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
		handleDashboardZeroConfMessage(notif.Payload)
	case NoticeConfigUpdate:
		handleNewConfiguration(notif.Payload)
	case NoticeDashboardConfigRequest:
		handleSendMiniConfig(notif.Payload)
	case NoticeGatewayDRLNotification:
		if config.Global.ManagementNode {
			// DRL is not initialized, going through would
			// be mostly harmless but would flood the log
			// with warnings since DRLManager.Ready == false
			return
		}
		onServerStatusReceivedHandler(notif.Payload)
	case NoticeGatewayLENotification:
		onLESSLStatusReceivedHandler(notif.Payload)
	case NoticeApiUpdated, NoticeApiRemoved, NoticeApiAdded, NoticePolicyChanged, NoticeGroupReload:
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("Reloading endpoints")
		reloadURLStructure(reloaded)
	default:
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Warnf("Unknown notification command: %q", notif.Command)
		return
	}
	if handled != nil {
		// went through. all others shoul have returned early.
		handled(notif.Command)
	}
}

var redisInsecureWarn sync.Once
var notificationVerifier goverify.Verifier

func isPayloadSignatureValid(notification Notification) bool {
	switch notification.Command {
	case NoticeGatewayDRLNotification, NoticeGatewayLENotification:
		// Gateway to gateway
		return true
	}

	if notification.Signature == "" && config.Global.AllowInsecureConfigs {
		redisInsecureWarn.Do(func() {
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
			}).Warning("Insecure configuration detected (allowing)!")
		})
		return true
	}

	if config.Global.PublicKeyPath != "" && notificationVerifier == nil {
		var err error
		notificationVerifier, err = goverify.LoadPublicKeyFromFile(config.Global.PublicKeyPath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "pub-sub",
			}).Error("Notification signer: Failed loading private key from path: ", err)
			return false
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

// RedisNotifier will use redis pub/sub channels to send notifications
type RedisNotifier struct {
	store   *storage.RedisCluster
	channel string
}

// Notify will send a notification to a channel
func (r *RedisNotifier) Notify(notification Notification) bool {
	toSend, err := json.Marshal(notification)
	if err != nil {
		log.Error("Problem marshalling notification: ", err)
		return false
	}
	log.Debug("Sending notification", notification)
	if err := r.store.Publish(r.channel, string(toSend)); err != nil {
		log.Error("Could not send notification: ", err)
		return false
	}
	return true
}
