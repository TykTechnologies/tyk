package main

import (
	"encoding/json"
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/drl"
	"github.com/TykTechnologies/tyk/config"
)

var DRLManager = &drl.DRL{}

func setupDRL() {
	drlManager := &drl.DRL{}
	drlManager.Init()
	drlManager.ThisServerID = NodeID + "|" + hostDetails.Hostname
	log.Debug("DRL: Setting node ID: ", drlManager.ThisServerID)
	DRLManager = drlManager
}

func startRateLimitNotifications() {
	notificationFreq := config.Global.DRLNotificationFrequency
	if notificationFreq == 0 {
		notificationFreq = 2
	}

	go func() {
		log.Info("Starting gateway rate limiter notifications...")
		for {
			if NodeID != "" {
				NotifyCurrentServerStatus()
			} else {
				log.Warning("Node not registered yet, skipping DRL Notification")
			}

			time.Sleep(time.Duration(notificationFreq) * time.Second)
		}
	}()
}

func getTagHash() string {
	th := ""
	for _, tag := range config.Global.DBAppConfOptions.Tags {
		th += tag
	}
	return th
}

func NotifyCurrentServerStatus() {
	if !DRLManager.Ready {
		return
	}

	rate := GlobalRate.Rate()
	if rate == 0 {
		rate = 1
	}

	server := drl.Server{
		HostName:   hostDetails.Hostname,
		ID:         NodeID,
		LoadPerSec: rate,
		TagHash:    getTagHash(),
	}

	asJson, err := json.Marshal(server)
	if err != nil {
		log.Error("Failed to encode payload: ", err)
		return
	}

	n := Notification{
		Command: NoticeGatewayDRLNotification,
		Payload: string(asJson),
	}

	MainNotifier.Notify(n)
}

func onServerStatusReceivedHandler(payload string) {
	serverData := drl.Server{}
	if err := json.Unmarshal([]byte(payload), &serverData); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed unmarshal server data: ", err)
		return
	}

	log.Debug("Received DRL data: ", serverData)

	if DRLManager.Ready {
		DRLManager.AddOrUpdateServer(serverData)
		log.Debug(DRLManager.Report())
	} else {
		log.Warning("DRL not ready, skipping this notification")
	}
}
