package streams

import (
	"fmt"
	"io"

	"github.com/buger/jsonparser"
	"github.com/sirupsen/logrus"
)

const (
	bentoLogMessageField = "msg"
	bentoLogLevelField   = "level"
)

// bentoLogAdapter translates Bento logs to Tyk logs and applies our logging conventions
type bentoLogAdapter struct {
	logger *logrus.Entry
}

func newBentoLogAdapter(logger *logrus.Entry) *bentoLogAdapter {
	return &bentoLogAdapter{logger: logger}
}

// bentoLogLine represents a structured log entry with a log level, a message, and additional fields.
type bentoLogLine struct {
	// log level
	level logrus.Level

	// log message
	msg string

	// All other fields
	fields map[string]interface{}
}

// Write processes a log entry in JSON format, parses its fields, and logs the message using the embedded logger.
// Returns the number of bytes written (always 0) and an error if parsing fails.
func (w *bentoLogAdapter) Write(p []byte) (n int, err error) {
	line := bentoLogLine{
		fields: make(map[string]interface{}),
	}
	err = jsonparser.ObjectEach(p, func(key []byte, value []byte, dataType jsonparser.ValueType, _ int) error {
		if string(key) == "time" {
			// discard time, the own logger of Tyk has this field
			return nil
		}
		if (string(key) == bentoLogMessageField) && (dataType == jsonparser.String) {
			line.msg = string(value)
		} else if (string(key) == bentoLogLevelField) && (dataType == jsonparser.String) {
			var logrusErr error
			line.level, logrusErr = logrus.ParseLevel(string(value))
			if logrusErr != nil {
				line.level = logrus.InfoLevel
			}
		} else {
			line.fields["bento_"+string(key)] = string(value)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("error while parsing Bento log line: '%s': %w", string(p), err)
	}

	logger := w.logger
	for k, v := range line.fields {
		logger = logger.WithField(k, v)
	}
	logger.Logln(line.level, line.msg)
	return 0, err
}

// Interface guard
var _ io.Writer = (*bentoLogAdapter)(nil)
