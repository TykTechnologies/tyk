package main

import (
	"rsc.io/letsencrypt"
	"encoding/json"
	"github.com/TykTechnologies/logrus"
)

const LEKeyPrefix string = "le_ssl:"

func StoreLEState(m *letsencrypt.Manager) {
	log.Debug("Storing SSL backup")
	
	log.Debug("[SSL] --> Connecting to DB")

	thisStore := &RedisClusterStorageManager{KeyPrefix: LEKeyPrefix, HashKeys: false}
	connected := thisStore.Connect()

	log.Debug("--> Connected to DB")

	if !connected {
		log.Error("[SSL] --> SSL Backup save failed: redis connection failed")
		return
	}

	state := m.Marshal()
	secret := rightPad2Len(config.Secret, "=", 32)
	cryptoText := encrypt([]byte(secret), state)

	rErr := thisStore.SetKey("cache", cryptoText, -1)
	if rErr != nil {
		log.Error("[SSL] --> Failed to store SSL backup: ", rErr)
		return
	}
}

func GetLEState(m *letsencrypt.Manager) {
	checkKey := "cache"

	thisStore := &RedisClusterStorageManager{KeyPrefix: LEKeyPrefix, HashKeys: false}

	connected := thisStore.Connect()
	log.Debug("[SSL] --> Connected to DB")

	if !connected {
		log.Error("[SSL] --> SSL Backup recovery failed: redis connection failed")
		return
	}

	cryptoText, rErr := thisStore.GetKey(checkKey)
	if rErr != nil {
		log.Warning("[SSL] --> No SSL backup: ", rErr)
		return
	}

	secret := rightPad2Len(config.Secret, "=", 32)
	sslState := decrypt([]byte(secret), cryptoText)

	m.Unmarshal(sslState)
}


type LE_ServerInfo struct {
	HostName string
	ID string
}

func NotifyLEStateChange() {
	thisServer := LE_ServerInfo{
		HostName:   HostDetails.Hostname,
		ID:         NodeID,
	}

	asJson, jsErr := json.Marshal(thisServer)
	if jsErr != nil {
		log.Error("Failed to encode payload: ", jsErr)
		return
	}

	n := Notification{
		Command: NoticeGatewayLENotification,
		Payload: string(asJson),
	}

	MainNotifier.Notify(n)
}

func OnLESSLStatusReceivedHandler(payload string) {
	thisServerData := LE_ServerInfo{}
	jsErr := json.Unmarshal([]byte(payload), &thisServerData)
	if jsErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed unmarshal server data: ", jsErr)
		return
	}

	log.Debug("Received LE data: ", thisServerData)

	// not great
	if thisServerData.ID != NodeID {
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