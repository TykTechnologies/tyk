package gateway

import (
	"encoding/json"

	"rsc.io/letsencrypt"

	"github.com/TykTechnologies/tyk/storage"
)

const LEKeyPrefix = "le_ssl:"

func (gw *Gateway) StoreLEState(m *letsencrypt.Manager) {
	letsencryptLog.Debug("Storing SSL backup")

	letsencryptLog.Debug("[SSL] --> Connecting to DB")

	store := storage.RedisCluster{KeyPrefix: LEKeyPrefix, RedisController: gw.RedisController}
	connected := store.Connect()

	letsencryptLog.Debug("--> Connected to DB")

	if !connected {
		letsencryptLog.Error("[SSL] --> SSL Backup save failed: redis connection failed")
		return
	}

	state := m.Marshal()
	secret := rightPad2Len(gw.GetConfig().Secret, "=", 32)
	cryptoText := encrypt([]byte(secret), state)

	if err := store.SetKey("cache", cryptoText, -1); err != nil {
		letsencryptLog.Error("[SSL] --> Failed to store SSL backup: ", err)
		return
	}
}

func (gw *Gateway) GetLEState(m *letsencrypt.Manager) {
	checkKey := "cache"

	store := storage.RedisCluster{KeyPrefix: LEKeyPrefix, RedisController: gw.RedisController}

	connected := store.Connect()
	letsencryptLog.Debug("[SSL] --> Connected to DB")

	if !connected {
		letsencryptLog.Error("[SSL] --> SSL Backup recovery failed: redis connection failed")
		return
	}

	cryptoText, err := store.GetKey(checkKey)
	if err != nil {
		letsencryptLog.Warning("[SSL] --> No SSL backup: ", err)
		return
	}

	secret := rightPad2Len(gw.GetConfig().Secret, "=", 32)
	sslState := decrypt([]byte(secret), cryptoText)

	m.Unmarshal(sslState)
}

type LE_ServerInfo struct {
	HostName string
	ID       string
}

func (gw *Gateway) onLESSLStatusReceivedHandler(payload string) {
	serverData := LE_ServerInfo{}
	if err := json.Unmarshal([]byte(payload), &serverData); err != nil {
		letsencryptLog.WithError(err).Error("Failed to unmarshal server data")
		return
	}

	if serverData.ID != gw.GetNodeID() {
		gw.GetLEState(&gw.LE_MANAGER)
	}
}

func (gw *Gateway) StartPeriodicStateBackup(m *letsencrypt.Manager) {
	watch := m.Watch()

	for {
		select {
		case <-gw.ctx.Done():
			return
		case <-watch:
			if gw.LE_FIRSTRUN {
				letsencryptLog.Info("[SSL] State change detected, storing")
				gw.StoreLEState(m)
			}
			gw.LE_FIRSTRUN = true
		}
	}
}
