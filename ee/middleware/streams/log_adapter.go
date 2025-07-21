package streams

import (
	"github.com/buger/jsonparser"
	"github.com/sirupsen/logrus"
)

const (
	bentoLogMessageField = "msg"
	bentoLogLevelField   = "level"
)

type bentoLogAdapter struct {
	logger *logrus.Entry
}

type bentoLogLine struct {
	// log level
	level logrus.Level

	// log message
	msg string

	// All other fields
	fields map[string]interface{}
}

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
			line.fields[string(key)] = string(value)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	logger := w.logger
	for k, v := range line.fields {
		logger = logger.WithField(k, v)
	}
	logger.Logln(line.level, line.msg)
	return n, err
}
