package log

import (
	"io"

	"github.com/sirupsen/logrus"
)

type Builder struct {
	sinkers                []SinkerExtended
	hooks                  []logrus.Hook
	level                  *logrus.Level
	stdLog                 *logrus.Logger
	rawLog                 *logrus.Logger
	withApplyHooksToRawLog bool
	propagate              bool
	discardOutput          bool
	legacyLogFormatEnabled bool
}

// WithLevel sets level.
func (b *Builder) WithLevel(level logrus.Level) {
	b.level = &level
}

// WithDiscardOutput discard output.
func (b *Builder) WithDiscardOutput() {
	b.discardOutput = true
}

// AddHook adds hook.
func (b *Builder) AddHook(hook logrus.Hook) {
	b.hooks = append(b.hooks, hook)
}

// AddSinker adds sinker.
func (b *Builder) AddSinker(sink ...SinkerExtended) {
	b.sinkers = append(b.sinkers, sink...)
}

// WithPropagate propagates logger.
func (b *Builder) WithPropagate() {
	b.propagate = true
}

// WithStdLog added for testing.
func (b *Builder) WithStdLog(log *logrus.Logger) {
	b.stdLog = log
}

// WithApplyHooksToRawLog set raw log to propagate hooks.
func (b *Builder) WithApplyHooksToRawLog() {
	b.withApplyHooksToRawLog = true
}

// WithRawLog set raw log to propagate hooks.
func (b *Builder) WithRawLog(log *logrus.Logger) {
	b.rawLog = log
}

func (b *Builder) SetLogformat(val Format) {
	b.legacyLogFormatEnabled = val == FormatLegacy
}

func (b *Builder) buildAndPropagate(dest *Logger) {
	var logrusStdLog = logrus.StandardLogger()

	if b.stdLog != nil {
		logrusStdLog = b.stdLog
	}
	b.applyHooksToRawLog()

	if b.level != nil {
		for _, sinker := range b.sinkers {
			sinker.SetAcceptor(NewAcceptorRange(*b.level, logrus.FatalLevel))
		}
	}

	dest.legacyLogFormatEnabled = b.legacyLogFormatEnabled
	b.discardLogger(dest.innerLogger)
	b.applyHooksAndSinks(dest.innerLogger)

	if b.propagate {
		b.discardLogger(logrusStdLog)
		b.applyHooksAndSinks(logrusStdLog)
	}
}

func (b *Builder) discardLogger(target *logrus.Logger) {
	var level = target.Level
	target.SetFormatter(&dummyFormatter{})
	target.SetOutput(io.Discard)
	target.SetLevel(level)
}

func (b *Builder) convertSinkers() []Sinker {
	if b.sinkers == nil {
		return nil
	}
	sinks := make([]Sinker, 0, len(b.sinkers))
	for _, sink := range b.sinkers {
		sinks = append(sinks, sink)
	}
	return sinks
}

func (b *Builder) applyHooksAndSinks(target *logrus.Logger) {
	for _, hook := range b.hooks {
		target.AddHook(hook)
	}

	if !b.discardOutput && len(b.sinkers) > 0 {
		target.AddHook(&multiSinkHook{
			sinks: b.convertSinkers(),
		})
	}
}

func (b *Builder) applyHooksToRawLog() {
	if !b.withApplyHooksToRawLog {
		return
	}

	target := rawLog

	if b.rawLog != nil {
		target = b.rawLog
	}

	for _, hook := range b.hooks {
		target.AddHook(hook)
	}
}

type dummyFormatter struct{}

func (d *dummyFormatter) Format(_ *logrus.Entry) ([]byte, error) {
	return nil, nil
}
