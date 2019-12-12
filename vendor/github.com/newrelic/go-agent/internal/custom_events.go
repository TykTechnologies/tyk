package internal

import (
	"time"
)

type customEvents struct {
	*analyticsEvents
}

func newCustomEvents(max int) *customEvents {
	return &customEvents{
		analyticsEvents: newAnalyticsEvents(max),
	}
}

func (cs *customEvents) Add(e *CustomEvent) {
	// For the Go Agent, customEvents are added to the application, not the transaction.
	// As a result, customEvents do not inherit their priority from the transaction, though
	// they are still sampled according to priority sampling.
	priority := NewPriority()
	cs.addEvent(analyticsEvent{priority, e})
}

func (cs *customEvents) MergeIntoHarvest(h *Harvest) {
	h.CustomEvents.mergeFailed(cs.analyticsEvents)
}

func (cs *customEvents) Data(agentRunID string, harvestStart time.Time) ([]byte, error) {
	return cs.CollectorJSON(agentRunID)
}

func (cs *customEvents) EndpointMethod() string {
	return cmdCustomEvents
}
