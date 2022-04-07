package gateway

import (
	"encoding/json"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/drl"
)

func (gw *Gateway) setupDRL() {
	drlManager := &drl.DRL{}
	drlManager.Init()
	drlManager.ThisServerID = gw.GetNodeID() + "|" + gw.hostDetails.Hostname
	log.Debug("DRL: Setting node ID: ", drlManager.ThisServerID)
	gw.DRLManager = drlManager
}

func (gw *Gateway) startRateLimitNotifications() {
	notificationFreq := gw.GetConfig().DRLNotificationFrequency
	if notificationFreq == 0 {
		notificationFreq = 2
	}

	go func() {
		log.Info("Starting gateway rate limiter notifications...")
		for {
			select {
			case <-gw.ctx.Done():
				return
			default:
				if gw.GetNodeID() != "" {
					gw.NotifyCurrentServerStatus()
				} else {
					log.Warning("Node not registered yet, skipping DRL Notification")
				}

				time.Sleep(time.Duration(notificationFreq) * time.Second)
			}

		}
	}()
}

func (gw *Gateway) getTagHash() string {
	th := ""
	for _, tag := range gw.GetConfig().DBAppConfOptions.Tags {
		th += tag
	}
	return th
}

func (gw *Gateway) NotifyCurrentServerStatus() {
	if gw.DRLManager == nil || !gw.DRLManager.Ready {
		return
	}

	rate := GlobalRate.Rate()
	if rate == 0 {
		rate = 1
	}

	server := drl.Server{
		HostName:   gw.hostDetails.Hostname,
		ID:         gw.GetNodeID(),
		LoadPerSec: rate,
		TagHash:    gw.getTagHash(),
	}

	asJson, err := json.Marshal(server)
	if err != nil {
		log.Error("Failed to encode payload: ", err)
		return
	}

	n := Notification{
		Command: NoticeGatewayDRLNotification,
		Payload: string(asJson),
		Gw:      gw,
	}

	gw.MainNotifier.Notify(n)
}

func (gw *Gateway) onServerStatusReceivedHandler(payload string) {
	if gw.DRLManager == nil || !gw.DRLManager.Ready {
		log.Warning("DRL not ready, skipping this notification")

		return
	}

	serverData := drl.Server{}
	if err := json.Unmarshal([]byte(payload), &serverData); err != nil {
		log.WithFields(logrus.Fields{
			"prefix":  "pub-sub",
			"payload": string(payload),
		}).Error("Failed unmarshal server data: ", err)
		return
	}

	if err := gw.DRLManager.AddOrUpdateServer(serverData); err != nil {
		log.WithError(err).
			WithField("serverData", serverData).
			Debug("AddOrUpdateServer error. Seems like you running multiple segmented Tyk groups in same Redis.")
		return
	}
}
