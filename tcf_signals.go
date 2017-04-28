package main

import (
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk-cluster-framework/payloads"
)

func startSubscription() {
	if PubSubClient == nil {
		StartGlobalClient(config.PubSubMasterConnectionString)
	}

	if err := PubSubClient.Subscribe(RedisPubSubChannel, func(payload payloads.Payload) {
		handleNotificationEvent(payload, nil, nil)
	}); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "tcf-pub-sub",
			"err":    err,
		}).Error("Connection to Master pub/sub failed, reconnect in 10s")

		time.Sleep(10 * time.Second)
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Warning("Reconnecting")

		err := PubSubClient.Start(config.PubSubMasterConnectionString)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func handleNotificationEvent(v payloads.Payload, handled func(NotificationCommand), reloaded func()) {
	notif := Notification{}
	if err := v.DecodeMessage(&notif); err != nil {
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
		if config.ManagementNode {
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
		}).Warnf("Unknown tcf notification command: %q", notif.Command)
		return
	}
	if handled != nil {
		// went through. all others shoul have returned early.
		handled(notif.Command)
	}
}
