package log

import (
	"io"

	"github.com/sirupsen/logrus"
)

type Builder struct {
	sinks         []Sink
	hooks         []logrus.Hook
	level         *logrus.Level
	stdLog        *logrus.Logger
	propagate     bool
	discardOutput bool
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

// WithPropagate propagates logger.
func (b *Builder) WithPropagate() {
	b.propagate = true
}

// WithStdLog added for testing.
func (b *Builder) WithStdLog(log *logrus.Logger) {
	b.stdLog = log
}

func (b *Builder) Build() *logrus.Logger {
	var logger = logrus.New()

	var level = logger.Level
	var stdLog = logrus.StandardLogger()

	if b.level != nil {
		level = *b.level
	}

	if b.stdLog != nil {
		stdLog = b.stdLog
	}

	logger.SetFormatter(&dummyFormatter{})
	logger.SetOutput(io.Discard)
	logger.SetLevel(level)

	if !b.discardOutput && len(b.sinks) > 0 {
		logger.Hooks.Add(&multiSinkHook{
			sinks: b.sinks,
		})
	}

	if b.propagate {
		stdLog.SetOutput(io.Discard)
		stdLog.SetFormatter(logger.Formatter)
		stdLog.SetLevel(level)

		if !b.discardOutput && len(b.sinks) > 0 {
			stdLog.Hooks.Add(&multiSinkHook{
				sinks: b.sinks,
			})
		}
	}

	return logger
}

type dummyFormatter struct{}

func (d *dummyFormatter) Format(_ *logrus.Entry) ([]byte, error) {
	return nil, nil
}
