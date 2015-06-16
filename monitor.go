package main

import "time"

type Monitor struct{}

func (m Monitor) IsMonitorEnabled() bool {
	if config.Monitor.EnableTriggerMonitors {
		return true
	}

	return false
}

func (m Monitor) Fire(sessionData *SessionState, key string, triggerLimit float64) {
	em := EventMessage{
		EventType: EVENT_TriggerExceeded,
		EventMetaData: EVENT_TriggerExceededMeta{
			EventMetaDefault: EventMetaDefault{Message: "Quota trigger reached", OriginatingRequest: ""},
			Org:              sessionData.OrgID,
			Key:              key,
			TriggerLimit:     int64(triggerLimit),
		},
		TimeStamp: time.Now().String(),
	}

	go MonitoringHandler.HandleEvent(em)
}

func (m Monitor) Check(sessionData *SessionState, key string) {
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

	if config.Monitor.GlobalTriggerLimit > 0.0 {
		if usagePerc >= config.Monitor.GlobalTriggerLimit {
			m.Fire(sessionData, key, config.Monitor.GlobalTriggerLimit)
		}
	}

	for _, triggerLimit := range sessionData.Monitor.TriggerLimits {
		if usagePerc >= triggerLimit {

			if triggerLimit != config.Monitor.GlobalTriggerLimit {
				m.Fire(sessionData, key, triggerLimit)
				break
			}

		}
	}
}
