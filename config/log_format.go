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

func (o *LogFormat) Type() LogFormatType {
	return o.formatType
}

func (o *LogFormat) Format() (tyklog.Format, bool) {
	return o.format, o.formatType == LogFormatString
}

func (o *LogFormat) Sinks() ([]tyklog.SinkConfig, bool) {
	return o.sinks, o.formatType == LogFormatSinks
}

func (o *LogFormat) UnmarshalJSON(data []byte) error {
	if string(data) == "null" || string(data) == `""` {
		return nil
	}

	var errs []error

	var legacyStr tyklog.Format
	if err := json.Unmarshal(data, &legacyStr); err == nil {
		if !legacyStr.Valid() {
			return fmt.Errorf("invalid format %q", string(legacyStr))
		}

		o.formatType = LogFormatString
		o.format = legacyStr
		return nil
	} else {
		errs = append(errs, err)
	}

	var sinks []tyklog.SinkConfig
	if err := json.Unmarshal(data, &sinks); err == nil {
		o.formatType = LogFormatSinks
		o.sinks = sinks
		return nil
	} else {
		errs = append(errs, err)
	}

	return fmt.Errorf("invalid log_format: must be a string, null, or an array of tyklog.SinkConfig: %w", errors.Join(errs...))
}

func (o LogFormat) MarshalJSON() ([]byte, error) {
	switch o.formatType {
	case LogFormatString:
		return json.Marshal(o.format)
	case LogFormatSinks:
		return json.Marshal(o.sinks)
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
