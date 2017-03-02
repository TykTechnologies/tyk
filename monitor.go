package main

import "time"

type Monitor struct{}

func (m *Monitor) IsMonitorEnabled() bool {
	return config.Monitor.EnableTriggerMonitors
}

func (m *Monitor) Fire(sessionData *SessionState, key string, triggerLimit float64) {
	em := EventMessage{
		EventType: EventTriggerExceeded,
		EventMetaData: EventTriggerExceededMeta{
			EventMetaDefault: EventMetaDefault{Message: "Quota trigger reached", OriginatingRequest: ""},
			Org:              sessionData.OrgID,
			Key:              key,
			TriggerLimit:     int64(triggerLimit),
		},
		TimeStamp: time.Now().String(),
	}

	go MonitoringHandler.HandleEvent(em)
}

func (m *Monitor) Check(sessionData *SessionState, key string) {
	if !m.IsMonitorEnabled() {
		return
	}

	if sessionData.QuotaMax == -1 {
		return
	}

	var usagePerc float64
	remainder := sessionData.QuotaMax - sessionData.QuotaRemaining
	usagePerc = (float64(remainder) / float64(sessionData.QuotaMax)) * 100.0

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

	if config.Monitor.GlobalTriggerLimit > 0.0 {
		if usagePerc >= config.Monitor.GlobalTriggerLimit {
			log.Info("Firing...")
			m.Fire(sessionData, key, config.Monitor.GlobalTriggerLimit)
		}
	}

	for _, triggerLimit := range sessionData.Monitor.TriggerLimits {
		if usagePerc >= triggerLimit {

			if triggerLimit != config.Monitor.GlobalTriggerLimit {
				log.Info("Firing...")
				m.Fire(sessionData, key, triggerLimit)
				break
			}

		}
	}
}
