package main

import (
	"encoding/json"

	"rsc.io/letsencrypt"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

const LEKeyPrefix = "le_ssl:"

func StoreLEState(m *letsencrypt.Manager) {
	log.Debug("Storing SSL backup")

	log.Debug("[SSL] --> Connecting to DB")

	store := storage.RedisCluster{KeyPrefix: LEKeyPrefix}
	connected := store.Connect()

	log.Debug("--> Connected to DB")

	if !connected {
		log.Error("[SSL] --> SSL Backup save failed: redis connection failed")
		return
	}

	state := m.Marshal()
	secret := rightPad2Len(config.Global().Secret, "=", 32)
	cryptoText := encrypt([]byte(secret), state)

	if err := store.SetKey("cache", cryptoText, -1); err != nil {
		log.Error("[SSL] --> Failed to store SSL backup: ", err)
		return
	}
}

func GetLEState(m *letsencrypt.Manager) {
	checkKey := "cache"

	store := storage.RedisCluster{KeyPrefix: LEKeyPrefix}

	connected := store.Connect()
	log.Debug("[SSL] --> Connected to DB")

	if !connected {
		log.Error("[SSL] --> SSL Backup recovery failed: redis connection failed")
		return
	}

	cryptoText, err := store.GetKey(checkKey)
	if err != nil {
		log.Warning("[SSL] --> No SSL backup: ", err)
		return
	}

	secret := rightPad2Len(config.Global().Secret, "=", 32)
	sslState := decrypt([]byte(secret), cryptoText)

	m.Unmarshal(sslState)
}

type LE_ServerInfo struct {
	HostName string
	ID       string
}

func onLESSLStatusReceivedHandler(payload string) {
	serverData := LE_ServerInfo{}
	if err := json.Unmarshal([]byte(payload), &serverData); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed unmarshal server data: ", err)
		return
	}

	log.Debug("Received LE data: ", serverData)

	// not great
	if serverData.ID != NodeID {
		log.Info("Received Redis LE change notification!")
		GetLEState(&LE_MANAGER)
	}

	log.Info("Received Redis LE change notification from myself, ignoring")

}

func StartPeriodicStateBackup(m *letsencrypt.Manager) {
	for range m.Watch() {
		// First run will call a cache save that overwrites with null data
		if LE_FIRSTRUN {
			log.Info("[SSL] State change detected, storing")
			StoreLEState(m)
		}

		LE_FIRSTRUN = true
	}
}
