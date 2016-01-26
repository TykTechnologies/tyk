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
		err := CacheStore.StartPubSubHandler(RedisPubSubChannel, HandleRedisReloadMsg)
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
			CacheStore.StartPubSubHandler(RedisPubSubChannel, HandleRedisReloadMsg)
		}

	}
}

func HandleRedisReloadMsg(message redis.Message) {
	thisMessage := Notification{}
	err := json.Unmarshal(message.Data, &thisMessage)
	if err != nil {
		log.Error("Unmarshalling message body failed, malformed: ", err)
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "pub-sub",
	}).Info("Reloading endpoints")
	ReloadURLStructure()
}
