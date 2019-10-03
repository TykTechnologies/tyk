package internal

import (
	"bytes"
	"time"
)

// MarshalJSON is used for testing.
func (e *ErrorEvent) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 256))

	e.WriteJSON(buf)

	return buf.Bytes(), nil
}

// WriteJSON prepares JSON in the format expected by the collector.
// https://source.datanerd.us/agents/agent-specs/blob/master/Error-Events.md
func (e *ErrorEvent) WriteJSON(buf *bytes.Buffer) {
	w := jsonFieldsWriter{buf: buf}
	buf.WriteByte('[')
	buf.WriteByte('{')
	w.stringField("type", "TransactionError")
	w.stringField("error.class", e.Klass)
	w.stringField("error.message", e.Msg)
	w.floatField("timestamp", timeToFloatSeconds(e.When))
	w.stringField("transactionName", e.FinalName)

	sharedTransactionIntrinsics(&e.TxnEvent, &w)
	sharedBetterCATIntrinsics(&e.TxnEvent, &w)

	buf.WriteByte('}')
	buf.WriteByte(',')
	userAttributesJSON(e.Attrs, buf, destError, e.ErrorData.ExtraAttributes)
	buf.WriteByte(',')
	agentAttributesJSON(e.Attrs, buf, destError)
	buf.WriteByte(']')
}

type errorEvents struct {
	*analyticsEvents
}

func newErrorEvents(max int) *errorEvents {
	return &errorEvents{
		analyticsEvents: newAnalyticsEvents(max),
	}
}

func (events *errorEvents) Add(e *ErrorEvent, priority Priority) {
	events.addEvent(analyticsEvent{priority, e})
}

func (events *errorEvents) MergeIntoHarvest(h *Harvest) {
	h.ErrorEvents.mergeFailed(events.analyticsEvents)
}

func (events *errorEvents) Data(agentRunID string, harvestStart time.Time) ([]byte, error) {
	return events.CollectorJSON(agentRunID)
}

func (events *errorEvents) EndpointMethod() string {
	return cmdErrorEvents
}
