package config

import (
	"encoding/json"
	"errors"
	"fmt"

	tyklog "github.com/TykTechnologies/tyk/log"
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

func (lf *LogFormat) UnmarshalJSON(data []byte) error {
	if string(data) == "null" || string(data) == `""` {
		return nil
	}

	var errs []error

	var legacyStr tyklog.Format
	if err := json.Unmarshal(data, &legacyStr); err == nil {
		if !legacyStr.Valid() {
			return fmt.Errorf("invalid format %q", string(legacyStr))
		}

		lf.formatType = LogFormatString
		lf.format = legacyStr
		return nil
	} else {
		errs = append(errs, err)
	}

	var sinks []tyklog.SinkConfig
	if err := json.Unmarshal(data, &sinks); err == nil {
		lf.formatType = LogFormatSinks
		lf.sinks = sinks
		return nil
	} else {
		errs = append(errs, err)
	}

	return fmt.Errorf("invalid log_format: must be a string, null, or an array of tyklog.SinkConfig: %w", errors.Join(errs...))
}

func (lf LogFormat) MarshalJSON() ([]byte, error) {
	switch lf.formatType {
	case LogFormatString:
		return json.Marshal(lf.format)
	case LogFormatSinks:
		return json.Marshal(lf.sinks)
	case LogFormatUndefined:
		fallthrough
	default:
		return []byte("null"), nil
	}
}

type LogFormatType int

const (
	LogFormatUndefined LogFormatType = iota
	LogFormatString
	LogFormatSinks
)
