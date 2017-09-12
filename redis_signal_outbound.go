package main

import (
	"encoding/json"
	"time"

	"github.com/Sirupsen/logrus"
)

type InterfaceNotification struct {
	Type      string
	Message   string
	OrgID     string
	Timestamp time.Time
}

type RedisNotificationHandler struct {
	CacheStore *RedisClusterStorageManager
}

const (
	UIChanName = "dashboard.ui.messages"
)

func (u *RedisNotificationHandler) Start() {
	go u.StartUIPubSubConn()
}

func (u *RedisNotificationHandler) Notify(n InterfaceNotification) error {
	jsonError, err := json.Marshal(n)
	if err != nil {
		return err
	}

	if u.CacheStore != nil {
		u.CacheStore.Publish(UIChanName, string(jsonError))
	}

	return nil
}

func (u *RedisNotificationHandler) StartUIPubSubConn() {
	u.CacheStore = &RedisClusterStorageManager{KeyPrefix: "gateway-notifications:"}
	u.CacheStore.Connect()
	// On message, synchronize
	for {
		err := u.CacheStore.StartPubSubHandler(UIChanName, u.HandleIncommingRedisEvent)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "log-notifications",
				"err":    err,
			}).Error("Connection to Redis failed, reconnect in 10s")

			time.Sleep(10 * time.Second)
			log.WithFields(logrus.Fields{
				"prefix": "log-notifications",
			}).Warning("Reconnecting")
		}

	}
}

func (u *RedisNotificationHandler) HandleIncommingRedisEvent(v interface{}) {
	log.Debug("Inbound redis event received")
}
