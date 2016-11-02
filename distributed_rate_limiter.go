package main

import (
	"encoding/json"
	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/drl"
	"time"
)

var DRLManager drl.DRL

func SetupDRL() {
	thisDRLManager := drl.DRL{}
	thisDRLManager.Init()
	thisDRLManager.ThisServerID = NodeID + "|" + HostDetails.Hostname
	log.Debug("DRL: Setting node ID: ", thisDRLManager.ThisServerID)
	DRLManager = thisDRLManager
}

func StartRateLimitNotifications() {
	notificationFreq := config.DRLNotificationFrequency
	if notificationFreq == 0 {
		notificationFreq = 2
	}

	go func() {
		log.Info("Starting gateway rate imiter notifications...")
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
	for _, tag := range(config.DBAppConfOptions.Tags) {
		th += tag
	}
	return th
}

func NotifyCurrentServerStatus() {
	if DRLManager.Ready == false {
		return
	}

	rate := GlobalRate.Rate()
	if rate == 0 {
		rate = 1
	}

	thisServer := drl.Server{
		HostName:   HostDetails.Hostname,
		ID:         NodeID,
		LoadPerSec: rate,
		TagHash:    getTagHash(),
	}

	asJson, jsErr := json.Marshal(thisServer)
	if jsErr != nil {
		log.Error("Failed to encode payload: ", jsErr)
		return
	}

	n := Notification{
		Command: NoticeGatewayDRLNotification,
		Payload: string(asJson),
	}

	MainNotifier.Notify(n)
}

func OnServerStatusReceivedHandler(payload string) {
	thisServerData := drl.Server{}
	jsErr := json.Unmarshal([]byte(payload), &thisServerData)
	if jsErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed unmarshal server data: ", jsErr)
		return
	}

	log.Debug("Received DRL data: ", thisServerData)

	if DRLManager.Ready {
		DRLManager.AddOrUpdateServer(thisServerData)
		log.Debug(DRLManager.Report())
	} else {
		log.Warning("DRL not ready, skipping this notification")
	}
}
