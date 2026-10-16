package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	tyklog "github.com/TykTechnologies/tyk/log"
)

type LogFormatType int

const (
	LogFormatUndefined LogFormatType = iota
	LogFormatString
	LogFormatSinks
)

type LogFormat struct {
	sinks      []tyklog.SinkConfig
	format     tyklog.Format
	formatType LogFormatType
}

func (lf *LogFormat) Type() LogFormatType {
	return lf.formatType
}

func (lf *LogFormat) Format() (tyklog.Format, bool) {
	return lf.format, lf.formatType == LogFormatString
}

func (lf *LogFormat) Sinks() ([]tyklog.SinkConfig, bool) {
	return lf.sinks, lf.formatType == LogFormatSinks
}

func (lf *LogFormat) Defined() bool {
	return lf.formatType != LogFormatUndefined
}

// UnmarshalJSON accepts null, any string, or an array of sinks.
// A string is stored as given; unknown names fall back to text when the logger is built (TT-18718
// covers validating them). An empty string or an empty array is the same as not set.
func (lf *LogFormat) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)

	switch {
	case string(data) == "null":
		return nil

	case bytes.HasPrefix(data, []byte(`"`)):
		var format tyklog.Format
		if err := json.Unmarshal(data, &format); err != nil {
			return err
		}
		if format == "" {
			return nil
		}
		lf.formatType = LogFormatString
		lf.format = format
		return nil

	case bytes.HasPrefix(data, []byte(`[`)):
		sinks, err := tyklog.ParseSinkConfigs(data)
		if err != nil {
			return err
		}
		if len(sinks) == 0 {
			return nil
		}
		lf.formatType = LogFormatSinks
		lf.sinks = sinks
		return nil
	}

	return errors.New("invalid log_format: must be a string, null, or an array of sink objects")
}

func (lf LogFormat) MarshalJSON() ([]byte, error) {
	switch lf.formatType {
	case LogFormatString:
		return json.Marshal(lf.format)
	case LogFormatSinks:
		return json.Marshal(lf.sinks)
	case LogFormatUndefined:
		return []byte("null"), nil
	default:
		return nil, errors.New("invalid invariant")
	}
}

// ParseLogFormatEnv parses an environment variable value: a JSON array of sinks, or a format name.
// Names are lowercased, as they always were for environment variables.
func ParseLogFormatEnv(raw string) (LogFormat, error) {
	raw = strings.TrimSpace(raw)

	var lf LogFormat
	if strings.HasPrefix(raw, "[") {
		err := lf.UnmarshalJSON([]byte(raw))
		return lf, err
	}

	if raw != "" {
		lf.formatType = LogFormatString
		lf.format = tyklog.Format(strings.ToLower(raw))
	}

	return lf, nil
}
