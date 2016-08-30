package main

import (
	"encoding/json"
	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/drl"
	"time"
)

// TODO:
/*

2. Add rate check to init so that we have a load indication

*/

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
		notificationFreq = 5
	}

	go func() {
		log.Info("Starting gateway rate imiter notifications...")
		for {
			NotifyCurrentServerStatus()
			time.Sleep(time.Duration(notificationFreq) * time.Second)
		}
	}()
}

func NotifyCurrentServerStatus() {
	rate := GlobalRate.Rate()
	if rate == 0 {
		rate = 1
	}

	thisServer := drl.Server{
		HostName:   HostDetails.Hostname,
		ID:         NodeID,
		LoadPerSec: rate,
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

	log.Debug("Sending DRL notification")

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

	DRLManager.AddOrUpdateServer(thisServerData)
}
