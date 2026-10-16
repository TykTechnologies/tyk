package log

import (
	"io"

	"github.com/sirupsen/logrus"
)

type Builder struct {
	sinkers                []Sinker
	hooks                  []logrus.Hook
	level                  *logrus.Level
	stdLog                 *logrus.Logger
	rawLog                 *logrus.Logger
	withApplyHooksToRawLog bool
	propagate              bool
	discardOutput          bool
	legacyLogFormatEnabled bool
}

// WithLevel sets the level at which entries are generated; sinks keep their own ranges.
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
func (b *Builder) AddSinker(sink ...Sinker) {
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
	if b.level != nil {
		level = *b.level
	}
	target.SetFormatter(&dummyFormatter{})
	target.SetOutput(io.Discard)
	target.SetLevel(level)
}

func (b *Builder) applyHooksAndSinks(target *logrus.Logger) {
	for _, hook := range b.hooks {
		target.AddHook(hook)
	}

	if !b.discardOutput && len(b.sinkers) > 0 {
		target.AddHook(&multiSinkHook{
			sinks: b.sinkers,
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
