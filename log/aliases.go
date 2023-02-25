package log

import (
	"io"

	"github.com/sirupsen/logrus"
)

type (
	Fields        = logrus.Fields
	Formatter     = logrus.Formatter
	JSONFormatter = logrus.JSONFormatter
	TextFormatter = logrus.TextFormatter
	Level         = logrus.Level
	LevelHooks    = logrus.LevelHooks
)

const (
	ErrorLevel Level = logrus.ErrorLevel
	PanicLevel Level = logrus.PanicLevel
	FatalLevel Level = logrus.FatalLevel
	InfoLevel  Level = logrus.InfoLevel
	DebugLevel Level = logrus.DebugLevel
	WarnLevel  Level = logrus.WarnLevel
)

type logger struct {
	*logrus.Entry
}

func (l *logger) Level() Level {
	return l.Entry.Level
}

func (l *logger) WithPrefix(prefix string) Logger {
	return l.WithField("prefix", prefix)
}

func (l *logger) WithField(key string, value interface{}) Logger {
	return &logger{l.Entry.WithField(key, value)}
}

func (l *logger) WithFields(fields Fields) Logger {
	return &logger{l.Entry.WithFields(fields)}
}

func (l *logger) WithError(err error) Logger {
	if err != nil {
		return &logger{l.Entry.WithError(err)}
	}
	return l
}

func (l *logger) ReplaceHooks(hooks LevelHooks) LevelHooks {
	return l.Entry.Logger.ReplaceHooks(hooks)
}

func (l *logger) SetLevel(level Level) {
	l.Entry.Logger.Level = level
}

func (l *logger) SetFormatter(formatter Formatter) {
	l.Entry.Logger.Formatter = formatter
}

func (l *logger) SetOutput(w io.Writer) {
	l.Entry.Logger.SetOutput(w)
}

var _ Logger = &logger{}

func newLogrusTextFormatter() *logrus.TextFormatter {
	return &logrus.TextFormatter{
		TimestampFormat: "Jan 02 15:04:05",
		FullTimestamp:   true,
		DisableColors:   true,
	}
}

func fromLogrusEntry(entry *logrus.Entry) Logger {
	return &logger{entry}
}

func fromLogrusLogger(logger *logrus.Logger) Logger {
	return fromLogrusEntry(logrus.NewEntry(logger))
}
