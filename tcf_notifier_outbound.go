package main

import (
	"github.com/TykTechnologies/tyk-cluster-framework/payloads"
)

// RedisNotifier will use redis pub/sub channels to send notifications
type TCFNotifier struct {
	channel string
}

// Notify will send a notification to a channel
func (r *TCFNotifier) Notify(notification interface{}) bool {
	toSend, err := payloads.NewPayload(notification)
	if err != nil {
		log.Error("Problem marshalling notification: ", err)
		return false
	}
	log.Debug("Sending notification", notification)

	if PubSubClient == nil {
		log.Warning("Client is nil, can't send notification")
		return false
	}

	if err := PubSubClient.Publish(r.channel, toSend); err != nil {
		log.Error("Could not send notification: ", err)
		return false
	}
	return true
}
