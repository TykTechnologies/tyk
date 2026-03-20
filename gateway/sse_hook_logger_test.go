package gateway

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoggingSSEHook_FilterEvent(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	entry := logrus.NewEntry(logger)

	h := NewLoggingSSEHook(entry)

	event := &SSEEvent{
		Event: "message",
		Data:  []string{"hello", "world"},
	}

	allowed, modified := h.FilterEvent(event)

	assert.True(t, allowed, "LoggingSSEHook must always allow events")
	assert.Nil(t, modified, "LoggingSSEHook must never modify events")

	require.Len(t, hook.Entries, 1)
	assert.Equal(t, logrus.DebugLevel, hook.Entries[0].Level)
	assert.Equal(t, "SSE event intercepted by hook", hook.Entries[0].Message)
	assert.Equal(t, "message", hook.Entries[0].Data["event_type"])
	assert.Equal(t, 2, hook.Entries[0].Data["data_lines"])
}

func TestLoggingSSEHook_VisibleLogs(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(os.Stderr)
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	entry := logrus.NewEntry(logger)

	h := NewLoggingSSEHook(entry)

	events := []*SSEEvent{
		{Event: "message", Data: []string{"hello"}},
		{Event: "endpoint", Data: []string{"/sse", "uri"}},
		{Event: "", Data: []string{"no-type"}},
	}

	for _, ev := range events {
		allowed, modified := h.FilterEvent(ev)
		assert.True(t, allowed)
		assert.Nil(t, modified)
	}
}

func TestLoggingSSEHook_ThroughSSETap(t *testing.T) {
	logger, _ := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	entry := logrus.NewEntry(logger)

	input := "event: ping\ndata: hello\n\nevent: update\ndata: world\n\n"
	body := io.NopCloser(strings.NewReader(input))

	tap := NewSSETap(body, NewLoggingSSEHook(entry))

	output, err := io.ReadAll(tap)
	require.NoError(t, err)
	assert.Equal(t, input, string(output), "events must pass through intact")
}
