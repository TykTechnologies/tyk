package streams

import (
	"bytes"
	"io"
	"regexp"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	bentoInfoLogLine = "{\"label\":\"\",\"level\":\"info\",\"msg\":\"Output type kafka " +
		"is now active\",\"path\":\"root.output.retry.output\",\"stream\":\"default_stream\"," +
		"\"time\":\"2025-07-16T11:38:20+03:00\"}\n"
	expectedInfoLogLine = "level=info msg=\"Output type kafka is now active\" " +
		"bento_label= bento_path=root.output.retry.output bento_stream=default_stream\n"

	bentoErrorLogLine = "{\"label\":\"\",\"level\":\"error\",\"msg\":\"Failed to send '1' messages: " +
		"kafka: client has run out of available brokers to talk to: read tcp [::1]:50152->[::1]:9092:" +
		" read: connection reset by peer\",\"path\":\"root.output.retry.output\",\"stream\":\"default_stream\"," +
		"\"time\":\"2025-07-16T11:38:29+03:00\"}\n"
	expectedErrorLogLine = "level=error msg=\"Failed to send '1' messages: kafka: client has run out of " +
		"available brokers to talk to: read tcp [::1]:50152->[::1]:9092: read: connection reset by peer\" " +
		"bento_label= bento_path=root.output.retry.output bento_stream=default_stream\n"

	bentoLogLineWithUndefinedLevel = "{\"label\":\"\",\"level\":\"undefined-level\",\"msg\":\"Output type kafka " +
		"is now active\",\"path\":\"root.output.retry.output\",\"stream\":\"default_stream\"," +
		"\"time\":\"2025-07-16T11:38:20+03:00\"}\n"
	expectedLogLineWithUndefinedLevel = "level=info msg=\"Output type kafka is now active\" " +
		"bento_label= bento_path=root.output.retry.output bento_stream=default_stream\n"
)

func newLogrusInstance(output io.Writer) *logrus.Entry {
	rootLogger := logrus.New()
	rootLogger.SetOutput(output)
	return logrus.NewEntry(rootLogger)
}

func pruneTimeSection(line string) string {
	re := regexp.MustCompile(`time="[^"]*"\s*`)
	return re.ReplaceAllString(line, "")
}

func TestBentoLogAdapter(t *testing.T) {
	type testDefinition struct {
		bentoLogLine       string
		expectedTykLogLine string
	}
	testDefinitions := []testDefinition{
		{
			bentoLogLine:       bentoInfoLogLine,
			expectedTykLogLine: expectedInfoLogLine,
		},
		{
			bentoLogLine:       bentoErrorLogLine,
			expectedTykLogLine: expectedErrorLogLine,
		},
		{
			bentoLogLine:       bentoLogLineWithUndefinedLevel,
			expectedTykLogLine: expectedLogLineWithUndefinedLevel,
		},
	}
	for _, definition := range testDefinitions {
		output := bytes.NewBuffer(nil)
		adapter := newBentoLogAdapter(newLogrusInstance(output))
		_, err := adapter.Write([]byte(definition.bentoLogLine))
		assert.Nil(t, err)
		assert.Equal(t, definition.expectedTykLogLine, pruneTimeSection(output.String()))
	}
}

func TestBentoLogAdapter_Corrupt_Log_Line(t *testing.T) {
	output := bytes.NewBuffer(nil)
	adapter := newBentoLogAdapter(newLogrusInstance(output))
	_, err := adapter.Write([]byte("{"))
	assert.ErrorContains(t, err, "error while parsing Bento log line: '{': Malformed JSON error")
}
