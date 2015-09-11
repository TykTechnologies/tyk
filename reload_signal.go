package main

import (
	"encoding/json"
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
			log.Error("Connection to Redis failed: err")
			time.Sleep(10 * time.Second)
			log.Warning("Reconnecting")
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

	log.Info("Reload signal received, reloading endpoints")
	ReloadURLStructure()
}
