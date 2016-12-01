package main

import (
	"encoding/json"
	"github.com/TykTechnologies/logrus"
	"github.com/garyburd/redigo/redis"
	"time"
)

type InterfaceNotification struct {
	Type      string
	Message   string
	OrgID     string
	Payload   interface{}
	Timestamp time.Time
}

type RedisNotificationHandler struct {
	CacheStore *RedisClusterStorageManager
}

const (
	UIChanName string = "dashboard.ui.messages"
)

func (u *RedisNotificationHandler) Start() {
	go u.StartUIPubSubConn()
}

func (u *RedisNotificationHandler) Notify(n InterfaceNotification) error {
	json_err, encErr := json.Marshal(n)
	if encErr != nil {
		return encErr
	}

	if u.CacheStore != nil {
		u.CacheStore.Publish(UIChanName, string(json_err))
	}

	return nil
}

func (u *RedisNotificationHandler) StartUIPubSubConn() {
	u.CacheStore = &RedisClusterStorageManager{KeyPrefix: "gateway-notifications:", HashKeys: false}
	u.CacheStore.Connect()
	// On message, synchronize
	for {
		err := u.CacheStore.StartPubSubHandler(UIChanName, u.HandleIncommingRedisMessage)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "log-notifications",
				"err":    err,
			}).Error("Connection to Redis failed, reconnect in 10s")

			time.Sleep(10 * time.Second)
			log.WithFields(logrus.Fields{
				"prefix": "log-notifications",
			}).Warning("Reconnecting")

			u.CacheStore.Connect()
			u.CacheStore.StartPubSubHandler(UIChanName, u.HandleIncommingRedisMessage)
		}

	}
}

func (u *RedisNotificationHandler) HandleIncommingRedisMessage(message redis.Message) {
	log.Debug("Inbound message received")
}
