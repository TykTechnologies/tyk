package log

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

type Builder struct {
	sinks                  []Sink
	hooks                  []logrus.Hook
	level                  *logrus.Level
	stdLog                 *logrus.Logger
	rawLog                 *logrus.Logger
	withApplyHooksToRawLog bool
	propagate              bool
	discardOutput          bool
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

// AddSink adds sink.
func (b *Builder) AddSink(sink Sink) {
	b.sinks = append(b.sinks, sink)
}

// AddSinkSplitByLevel adds default split by level.
// AddSink or AddDefaultSplit can be used.
// These methods are mutually excluded.
func (b *Builder) AddSinkSplitByLevel(level logrus.Level, formatter logrus.Formatter) {
	b.AddSink(NewSink(os.Stderr, formatter, NewAcceptorGte(level)))
	b.AddSink(NewSink(os.Stdout, formatter, NewAcceptorLt(level)))
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

func (b *Builder) BuildAndPropagate() *logrus.Logger {
	var logger = logrus.New()
	var stdLog = logrus.StandardLogger()

	if b.stdLog != nil {
		stdLog = b.stdLog
	}
	b.applyHooksToRawLog()

	b.discardLogger(logger)
	b.applyHooksAndSinks(logger)

	if b.propagate {
		b.discardLogger(stdLog)
		b.applyHooksAndSinks(stdLog)
	}

	return logger
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

	if !b.discardOutput && len(b.sinks) > 0 {
		target.AddHook(&multiSinkHook{
			sinks: b.sinks,
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
