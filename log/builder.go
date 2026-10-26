package log

import (
	"io"
	stdlog "log"
	"strings"

	"github.com/sirupsen/logrus"
)

type Builder struct {
	sinkers                []Sinker
	hooks                  []logrus.Hook
	level                  *logrus.Level
	stdLog                 *logrus.Logger
	propagate              bool
	discardOutput          bool
	legacyLogFormatEnabled bool
	stdlibLevel            *logrus.Level
	stdlibLogger           *stdlog.Logger
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

// RedirectStdlib turns Go's standard logger output into entries of the built logger
// at the given level, tagged prefix=system. Timestamps come from the formatter.
func (b *Builder) RedirectStdlib(level logrus.Level) {
	b.stdlibLevel = &level
}

// WithStdlibLogger sets the standard logger to redirect instead of the global one. Added for testing.
func (b *Builder) WithStdlibLogger(l *stdlog.Logger) {
	b.stdlibLogger = l
}

func (b *Builder) SetLogformat(val Format) {
	b.legacyLogFormatEnabled = val == FormatLegacy
}

func (b *Builder) buildAndPropagate(dest *Logger) {
	var logrusStdLog = logrus.StandardLogger()

	if b.stdLog != nil {
		logrusStdLog = b.stdLog
	}
	dest.legacyLogFormatEnabled = b.legacyLogFormatEnabled
	b.discardLogger(dest.innerLogger)
	b.applyHooksAndSinks(dest.innerLogger)

	if b.propagate {
		b.discardLogger(logrusStdLog)
		b.applyHooksAndSinks(logrusStdLog)
	}

	b.redirectStdlib(dest)
}

func (b *Builder) redirectStdlib(dest *Logger) {
	if b.stdlibLevel == nil {
		return
	}

	target := stdlog.Default()
	if b.stdlibLogger != nil {
		target = b.stdlibLogger
	}

	target.SetFlags(0)
	target.SetOutput(&stdlibWriter{entry: dest.WithField("prefix", "stdlib"), level: *b.stdlibLevel})
}

type stdlibWriter struct {
	entry *logrus.Entry
	level logrus.Level
}

func (w *stdlibWriter) Write(p []byte) (int, error) {
	w.entry.Log(w.level, strings.TrimRight(string(p), "\n"))
	return len(p), nil
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

type dummyFormatter struct{}

func (d *dummyFormatter) Format(_ *logrus.Entry) ([]byte, error) {
	return nil, nil
}
