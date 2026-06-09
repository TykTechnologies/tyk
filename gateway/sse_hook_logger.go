package gateway

import "github.com/sirupsen/logrus"

// LoggingSSEHook logs each SSE event flowing through the SSETap.
// It always allows events to pass through unmodified.
type LoggingSSEHook struct {
	logger *logrus.Entry
}

func NewLoggingSSEHook(logger *logrus.Entry) *LoggingSSEHook {
	return &LoggingSSEHook{logger: logger}
}

func (h *LoggingSSEHook) FilterEvent(event *SSEEvent) (bool, *SSEEvent) {
	h.logger.WithFields(logrus.Fields{
		"event_type": event.Event,
		"data_lines": len(event.Data),
	}).Debug("SSE event intercepted by hook")
	return true, nil
}
