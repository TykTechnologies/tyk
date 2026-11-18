package log

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
)

type Sinker interface {
	Sink(e *logrus.Entry)
}

type Acceptor interface {
	Accept(entry *logrus.Entry) bool
}

// sinkLevels are the severities a sink range may name; log_level keeps its own, narrower set.
var sinkLevels = map[string]logrus.Level{
	"panic": logrus.PanicLevel,
	"fatal": logrus.FatalLevel,
	"error": logrus.ErrorLevel,
	"warn":  logrus.WarnLevel,
	"info":  logrus.InfoLevel,
	"debug": logrus.DebugLevel,
}

func parseSinkLevel(field string, value Level, fallback logrus.Level) (logrus.Level, error) {
	if value == "" {
		return fallback, nil
	}

	level, ok := sinkLevels[strings.ToLower(string(value))]
	if !ok {
		return 0, fmt.Errorf("unknown %s %q", field, value)
	}

	return level, nil
}

func NewSink(
	writer io.Writer,
	formatter logrus.Formatter,
	acceptor Acceptor,
) *Sink {

	lgr := logrus.New()
	lgr.SetLevel(logrus.TraceLevel)
	lgr.SetFormatter(formatter)
	lgr.SetOutput(writer)
	lgr.ExitFunc = func(_ int) {} // skip exit in sub-loggers (sinks)

	return &Sink{
		logger:   lgr,
		acceptor: acceptor,
	}
}

// NewSinkFromConfig builds a sink. Level, format and output names are case-insensitive;
// anything missing or unrecognised is an error.
func NewSinkFromConfig(cfg SinkConfig) (*Sink, error) {
	lowLevel, err := parseSinkLevel("level", cfg.Level, logrus.InfoLevel)
	if err != nil {
		return nil, err
	}

	highLevel, err := parseSinkLevel("high_level", cfg.HighLevel, logrus.PanicLevel)
	if err != nil {
		return nil, err
	}

	if cfg.Output == "" {
		return nil, errors.New("missing output")
	}

	output, err := MakeOutput(Output(strings.ToLower(string(cfg.Output))), cfg.OutputOptions)
	if err != nil {
		return nil, err
	}

	if cfg.Format == "" {
		return nil, errors.New("missing format")
	}

	formatter, err := MakeFormatter(Format(strings.ToLower(string(cfg.Format))), cfg.FormatOptions)
	if err != nil {
		return nil, err
	}

	return NewSink(output, formatter, NewAcceptorRange(lowLevel, highLevel)), nil
}

// NewSinksFromConfig builds every sink; an error names the failing sink by its index.
func NewSinksFromConfig(cfgs []SinkConfig) ([]*Sink, error) {
	sinks := make([]*Sink, 0, len(cfgs))
	var errs []error

	for i, cfg := range cfgs {
		sink, err := NewSinkFromConfig(cfg)
		if err != nil {
			errs = append(errs, fmt.Errorf("log_format[%d]: %w", i, err))
			continue
		}
		sinks = append(sinks, sink)
	}

	return sinks, errors.Join(errs...)
}

// ParseSinkConfigs decodes a JSON array of sinks, rejecting unknown fields.
func ParseSinkConfigs(data []byte) ([]SinkConfig, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	sinks := make([]SinkConfig, 0, len(raw))
	for i, item := range raw {
		var sink SinkConfig
		dec := json.NewDecoder(bytes.NewReader(item))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&sink); err != nil {
			return nil, fmt.Errorf("log_format[%d]: %w", i, err)
		}
		sinks = append(sinks, sink)
	}

	return sinks, nil
}

// UncoveredLevels returns the levels from minLevel up to panic that no acceptor accepts.
func UncoveredLevels(minLevel logrus.Level, acceptors ...Acceptor) []logrus.Level {
	var uncovered []logrus.Level

	for level := logrus.PanicLevel; level <= minLevel; level++ {
		entry := &logrus.Entry{Level: level}
		covered := false
		for _, acceptor := range acceptors {
			if acceptor.Accept(entry) {
				covered = true
				break
			}
		}
		if !covered {
			uncovered = append(uncovered, level)
		}
	}

	return uncovered
}

type Sink struct {
	logger   *logrus.Logger
	acceptor Acceptor
}

func (a *Sink) Accept(entry *logrus.Entry) bool {
	return a.acceptor.Accept(entry)
}

func (a *Sink) Sink(entry *logrus.Entry) {
	if !a.Accept(entry) {
		return
	}

	clonedEntry := a.logger.WithFields(entry.Data)
	clonedEntry.Time = entry.Time
	clonedEntry.Log(entry.Level, entry.Message)
}

type multiSinkHook struct {
	sinks []Sinker
}

func (h *multiSinkHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *multiSinkHook) Fire(entry *logrus.Entry) error {
	for _, s := range h.sinks {
		s.Sink(entry)
	}

	return nil
}

// AcceptorFn
// Anonymous filter/acceptor.
// Normally log levels are trace < debug < info < warn < error.
// But logrus has reverted logic trace > debug > info > warn > error.
// Ensure you have provided the proper predicate.
type AcceptorFn func(e *logrus.Entry) bool

func (fn AcceptorFn) Accept(entry *logrus.Entry) bool {
	return fn(entry)
}

func NewAcceptorRange(minLevel, maxLevel logrus.Level) Acceptor {
	if minLevel > maxLevel {
		maxLevel, minLevel = minLevel, maxLevel
	}

	return AcceptorFn(func(e *logrus.Entry) bool {
		// ex. e.Level >= 2 (Error) && e.Level <= 4 (Info)
		return e.Level >= minLevel && e.Level <= maxLevel
	})
}

var (
	AcceptorAllowAll = AcceptorFn(func(_ *logrus.Entry) bool {
		return true
	})
)

// SinkConfig defines a single log sink, combining filtering rules
// (log level), message formatting, and the target output destination.
//
// The structure utilizes json.RawMessage for format and output options,
// implementing a lazy parsing pattern. This allows for registering
// custom formats and outputs without the need to modify this base
// configuration struct.
type SinkConfig struct {
	// Level specifies the minimum severity level (e.g., debug, info, warn)
	// an event must have to be processed by this sink.
	// low level
	Level Level `json:"level,omitempty"`

	// Level specifies the maximum severity level (e.g., debug, info, warn)
	// Default value: panic
	HighLevel Level `json:"high_level,omitempty"`

	// Format defines the identifier of the used formatter (e.g., "json", "text").
	// Based on this value, the system selects the appropriate formatter factory.
	Format Format `json:"format,omitempty"`

	// FormatOptions contains the raw JSON payload with parameters specific
	// to the chosen Format. This payload is passed directly to the
	// formatter factory, which decides what concrete structure to decode it into.
	// It can be omitted if the format requires no configuration.
	FormatOptions json.RawMessage `json:"format_options,omitempty"`

	// Output defines the identifier of the target destination (e.g., "file", "http", "stdout").
	// Based on this value, the system selects the appropriate output factory.
	Output Output `json:"output,omitempty"`

	// OutputOptions contains the raw JSON payload with parameters specific
	// to the chosen Output (e.g., file path, host address). This payload
	// is passed to the output factory to be decoded into a concrete type.
	// It can be omitted for outputs that do not require options (e.g., "stdout").
	OutputOptions json.RawMessage `json:"output_options,omitempty"`
}
