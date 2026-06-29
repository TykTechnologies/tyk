package gateway

import (
	"encoding/json"
	"math/rand"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/drl"
)

const (
	defaultDRLNotificationFrequency = 2 * time.Second
	idleDRLNotificationFrequency    = 30 * time.Second
)

func (gw *Gateway) startRateLimitNotifications() {
	notificationInterval := time.Duration(gw.GetConfig().DRLNotificationFrequency) * time.Second
	if notificationInterval == 0 {
		notificationInterval = defaultDRLNotificationFrequency
	}

	go func() {
		log.Info("Starting gateway rate limiter notifications...")
		lastIdleNotification := time.Now()
		if err := sleepWithContext(gw.ctx, drlNotificationInitialJitter(notificationInterval)); err != nil {
			return
		}

		for {
			select {
			case <-gw.ctx.Done():
				return
			default:
				if gw.GetNodeID() != "" {
					published, idle := gw.notifyCurrentServerStatusIfReady(lastIdleNotification)
					if published && idle {
						lastIdleNotification = time.Now()
					}
				} else {
					log.Warning("Node not registered yet, skipping DRL Notification")
				}

				if err := sleepWithContext(gw.ctx, notificationInterval); err != nil {
					return
				}
			}

		}
	}()
}

func drlNotificationInitialJitter(notificationInterval time.Duration) time.Duration {
	if notificationInterval <= 0 {
		return 0
	}

	return time.Duration(rand.Int63n(int64(notificationInterval)))
}

func (gw *Gateway) getTagHash() string {
	th := ""
	for _, tag := range gw.GetConfig().DBAppConfOptions.Tags {
		th += tag
	}
	return th
}

func (gw *Gateway) notifyCurrentServerStatusIfReady(lastIdleNotification time.Time) (bool, bool) {
	if !gw.controlPlaneReady.Load() {
		return false, false
	}

	rate := GlobalRate.Rate()
	idle := rate == 0
	if idle {
		if time.Since(lastIdleNotification) < idleDRLNotificationFrequency {
			return false, true
		}
		rate = 1
	}

	return gw.notifyCurrentServerStatusWithRate(rate), idle
}

func (gw *Gateway) NotifyCurrentServerStatus() bool {
	rate := GlobalRate.Rate()
	if rate == 0 {
		rate = 1
	}

	return gw.notifyCurrentServerStatusWithRate(rate)
}

func (gw *Gateway) notifyCurrentServerStatusWithRate(rate int64) bool {
	if gw.DRLManager == nil || !gw.DRLManager.Ready() {
		return false
	}

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
		return false
	}

	n := Notification{
		Command: NoticeGatewayDRLNotification,
		Payload: string(asJson),
		Gw:      gw,
	}

	return gw.MainNotifier.Notify(n)
}

func (gw *Gateway) onServerStatusReceivedHandler(payload string) {
	gw.startDRL()

	if !gw.DRLManager.Ready() {
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
