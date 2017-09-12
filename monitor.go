package main

import (
	"time"

	"github.com/TykTechnologies/tyk/config"
)

type Monitor struct{}

func (Monitor) IsMonitorEnabled() bool {
	return globalConf.Monitor.EnableTriggerMonitors
}

func (Monitor) Fire(sessionData *SessionState, key string, triggerLimit float64) {
	em := config.EventMessage{
		Type: EventTriggerExceeded,
		Meta: EventTriggerExceededMeta{
			EventMetaDefault: EventMetaDefault{Message: "Quota trigger reached"},
			Org:              sessionData.OrgID,
			Key:              key,
			TriggerLimit:     int64(triggerLimit),
		},
		TimeStamp: time.Now().String(),
	}

	go MonitoringHandler.HandleEvent(em)
}

func (m Monitor) Check(sessionData *SessionState, key string) {
	if !m.IsMonitorEnabled() || sessionData.QuotaMax == -1 {
		return
	}

	remainder := sessionData.QuotaMax - sessionData.QuotaRemaining
	usagePerc := (float64(remainder) / float64(sessionData.QuotaMax)) * 100.0

	log.Debug("Perc is: ", usagePerc)
	renewalDate := time.Unix(sessionData.QuotaRenews, 0)

	log.Debug("Now is: ", time.Now())
	log.Debug("Renewal is: ", renewalDate)
	if time.Now().After(renewalDate) {
		// Make sure that renewal is still in the future, If renewal is in the past,
		// then the quota can expire and will auto-renew
		log.Debug("Renewal date is in the past, skipping")
		return
	}

	if globalConf.Monitor.GlobalTriggerLimit > 0.0 && usagePerc >= globalConf.Monitor.GlobalTriggerLimit {
		log.Info("Firing...")
		m.Fire(sessionData, key, globalConf.Monitor.GlobalTriggerLimit)
	}

	for _, triggerLimit := range sessionData.Monitor.TriggerLimits {
		if usagePerc >= triggerLimit && triggerLimit != globalConf.Monitor.GlobalTriggerLimit {
			log.Info("Firing...")
			m.Fire(sessionData, key, triggerLimit)
			break
		}
	}
}
