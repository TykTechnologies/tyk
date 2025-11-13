package log

import (
	"bytes"

	"github.com/goccy/go-json"
	"github.com/sirupsen/logrus"
)

// JSONFormatter formats logs into parsable json.
type JSONFormatter struct {
	// TimestampFormat sets the format used for marshaling timestamps.
	// The format to use is the same than for time.Format or time.Parse from the standard
	// library.
	// The standard Library already provides a set of predefined format.
	TimestampFormat string

	// DisableTimestamp allows disabling automatic timestamps in output.
	DisableTimestamp bool

	// DataKey allows users to put all the log entry parameters into a nested dictionary at a given key.
	DataKey string
}

// Format renders a single log entry
func (f *JSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	data := make(logrus.Fields, len(entry.Data)+4)
	for k, v := range entry.Data {
		switch v := v.(type) {
		case error:
			// Otherwise errors are ignored by `encoding/json`
			// https://github.com/sirupsen/logrus/issues/137
			data[k] = v.Error()
		default:
			data[k] = v
		}
	}

	if f.DataKey != "" {
		newData := make(logrus.Fields, 4)
		newData[f.DataKey] = data
		data = newData
	}

	if v, ok := entry.Data[logrus.ErrorKey]; ok {
		if e, ok := v.(error); ok {
			data[logrus.FieldKeyLogrusError] = e.Error()
		} else {
			data[logrus.FieldKeyLogrusError] = v
		}
	}

	if !f.DisableTimestamp {
		data[logrus.FieldKeyTime] = entry.Time.Format(f.TimestampFormat)
	}
	data[logrus.FieldKeyMsg] = entry.Message
	data[logrus.FieldKeyLevel] = entry.Level.String()

	var w bytes.Buffer
	enc := json.NewEncoder(&w)
	err := enc.Encode(data)
	return w.Bytes(), err
}
