package main

import (
	"github.com/TykTechnologies/drl"
	"time"
	"encoding/json"
	"github.com/Sirupsen/logrus"
)

// TODO:
/*

1. How to update keys if the token changes? Need to be able to remove the token bucket
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
	go func() {
		log.Info("Starting gateway rate imiter notifications...")
		for {
			NotifyCurrentServerStatus()
			time.Sleep(5 * time.Second)
		}
	}()
}

func NotifyCurrentServerStatus() {
	thisServer := drl.Server{
		HostName:   HostDetails.Hostname,
		ID:         NodeID,
		LoadPerSec: 1000,
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
