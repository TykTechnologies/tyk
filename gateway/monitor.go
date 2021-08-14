package gateway

import (
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

type Monitor struct{}

func (Monitor) Enabled() bool {
	return config.Global().Monitor.EnableTriggerMonitors
}

func (Monitor) Fire(sessionData *user.SessionState, key string, triggerLimit, usagePercentage float64) {
	em := config.EventMessage{
		Type: EventTriggerExceeded,
		Meta: EventTriggerExceededMeta{
			EventMetaDefault: EventMetaDefault{Message: "Quota trigger reached"},
			OrgID:            sessionData.OrgID,
			Key:              key,
			TriggerLimit:     int64(triggerLimit),
			UsagePercentage:  int64(usagePercentage),
		},
		TimeStamp: time.Now().String(),
	}

	go MonitoringHandler.HandleEvent(em)
}

func (m Monitor) Check(sessionData *user.SessionState, key string) {
	if !m.Enabled() {
		return
	}

	if m.checkLimit(sessionData, key, sessionData.QuotaMax, sessionData.QuotaRemaining, sessionData.QuotaRenews) {
		return
	}

	for _, ac := range sessionData.AccessRights {
		if ac.Limit.IsEmpty() {
			continue
		}

		if m.checkLimit(sessionData, key, ac.Limit.QuotaMax, ac.Limit.QuotaRemaining, ac.Limit.QuotaRenews) {
			return
		}
	}
}

func (m Monitor) checkLimit(sessionData *user.SessionState, key string, quotaMax, quotaRemaining, quotaRenews int64) bool {
	if quotaMax <= 0 {
		return false
	}

	remainder := quotaMax - quotaRemaining
	usagePerc := (float64(remainder) / float64(quotaMax)) * 100.0

	log.Debug("Perc is: ", usagePerc)
	renewalDate := time.Unix(quotaRenews, 0)

	log.Debug("Now is: ", time.Now())
	log.Debug("Renewal is: ", renewalDate)
	if time.Now().After(renewalDate) {
		// Make sure that renewal is still in the future, If renewal is in the past,
		// then the quota can expire and will auto-renew
		log.Debug("Renewal date is in the past, skipping")
		return false
	}

	if config.Global().Monitor.GlobalTriggerLimit > 0.0 && usagePerc >= config.Global().Monitor.GlobalTriggerLimit {
		log.Info("Firing...")
		m.Fire(sessionData, key, config.Global().Monitor.GlobalTriggerLimit, usagePerc)
		return true
	}

	for _, triggerLimit := range sessionData.Monitor.TriggerLimits {
		if usagePerc >= triggerLimit && triggerLimit != config.Global().Monitor.GlobalTriggerLimit {
			log.Info("Firing...")
			m.Fire(sessionData, key, triggerLimit, usagePerc)
			return true
		}
	}

	return false
}
