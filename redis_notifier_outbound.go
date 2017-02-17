package main

import (
	"encoding/json"
)

type NotificationCommand string

const (
	NoticeGroupReload            NotificationCommand = "GroupReload"
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

// RedisNotifier will use redis pub/sub channels to send notifications
type RedisNotifier struct {
	store   *RedisClusterStorageManager
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
