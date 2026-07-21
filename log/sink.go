package log

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
)

type Sinker interface {
	Sink(e *logrus.Entry)
}

type AcceptorSetter interface {
	SetAcceptor(Acceptor)
}

type SinkerExtended interface {
	Sinker
	AcceptorSetter
}

type Acceptor interface {
	Accept(entry *logrus.Entry) bool
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

func NewSinkFromConfig(cfg SinkConfig) (*Sink, error) {
	lowLevel, ok := cfg.Level.LogrusLevel()
	if !ok {
		return nil, fmt.Errorf("invalid log level in config: %q", cfg.Level)
	}
	highLevel, ok := cfg.HighLevel.LogrusLevel()
	if !ok {
		highLevel = logrus.PanicLevel
	}
	acceptor := NewAcceptorRange(lowLevel, highLevel)

	output, err := MakeOutput(cfg.Output, cfg.OutputOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to make output: %w", err)
	}

	formatter, err := MakeFormatter(cfg.Format, cfg.FormatOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to make output: %w", err)
	}

	return NewSink(output, formatter, acceptor), nil
}

type Sink struct {
	logger   *logrus.Logger
	acceptor Acceptor
}

func (a *Sink) SetAcceptor(acceptor Acceptor) {
	a.acceptor = acceptor
}

func (a *Sink) Sink(entry *logrus.Entry) {
	if !a.acceptor.Accept(entry) {
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
