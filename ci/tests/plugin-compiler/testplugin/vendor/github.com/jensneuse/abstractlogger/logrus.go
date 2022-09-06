package abstractlogger

import (
	"github.com/sirupsen/logrus"
)

func NewLogrusLogger(l *logrus.Logger, level Level) *LogrusLogger {
	return &LogrusLogger{
		l:          l,
		levelCheck: NewLevelCheck(level),
	}
}

// LogrusLogger implements the Logger frontend using the popular logrus library as a backend
// It makes use of the LevelCheck helper to increase performance
type LogrusLogger struct {
	l          *logrus.Logger
	levelCheck LevelCheck
}

func (l *LogrusLogger) LevelLogger(level Level) LevelLogger {
	return &LogrusLevelLogger{
		l:     l.l,
		level: level,
	}
}

func (l *LogrusLogger) fields(fields []Field) logrus.Fields {
	out := make(logrus.Fields, len(fields))
	for i := range fields {
		switch fields[i].kind {
		case StringField:
			out[fields[i].key] = fields[i].stringValue
		case ByteStringField:
			out[fields[i].key] = string(fields[i].byteValue)
		case IntField:
			out[fields[i].key] = fields[i].intValue
		case BoolField:
			out[fields[i].key] = fields[i].intValue != 0
		case ErrorField, NamedErrorField:
			out[fields[i].key] = fields[i].errorValue
		case StringsField:
			out[fields[i].key] = fields[i].stringsValue
		default:
			out[fields[i].key] = fields[i].interfaceValue
		}
	}
	return out
}

func (l *LogrusLogger) Debug(msg string, fields ...Field) {
	if !l.levelCheck.Check(DebugLevel) {
		return
	}
	l.l.WithFields(l.fields(fields)).Debug(msg)
}

func (l *LogrusLogger) Info(msg string, fields ...Field) {
	if !l.levelCheck.Check(InfoLevel) {
		return
	}
	l.l.WithFields(l.fields(fields)).Info(msg)
}

func (l *LogrusLogger) Warn(msg string, fields ...Field) {
	if !l.levelCheck.Check(WarnLevel) {
		return
	}
	l.l.WithFields(l.fields(fields)).Warn(msg)
}

func (l *LogrusLogger) Error(msg string, fields ...Field) {
	if !l.levelCheck.Check(ErrorLevel) {
		return
	}
	l.l.WithFields(l.fields(fields)).Error(msg)
}

func (l *LogrusLogger) Fatal(msg string, fields ...Field) {
	if !l.levelCheck.Check(FatalLevel) {
		return
	}
	l.l.WithFields(l.fields(fields)).Fatal(msg)
}

func (l *LogrusLogger) Panic(msg string, fields ...Field) {
	if !l.levelCheck.Check(PanicLevel) {
		return
	}
	l.l.WithFields(l.fields(fields)).Panic(msg)
}

type LogrusLevelLogger struct {
	l     *logrus.Logger
	level Level
}

func (s *LogrusLevelLogger) Println(v ...interface{}) {
	switch s.level {
	case DebugLevel:
		s.l.Debug(v...)
	case InfoLevel:
		s.l.Info(v...)
	case WarnLevel:
		s.l.Warn(v...)
	case ErrorLevel:
		s.l.Error(v...)
	case FatalLevel:
		s.l.Fatal(v...)
	case PanicLevel:
		s.l.Panic(v...)
	}
}

func (s *LogrusLevelLogger) Printf(format string, v ...interface{}) {
	switch s.level {
	case DebugLevel:
		s.l.Debugf(format, v...)
	case InfoLevel:
		s.l.Infof(format, v...)
	case WarnLevel:
		s.l.Warnf(format, v...)
	case ErrorLevel:
		s.l.Errorf(format, v...)
	case FatalLevel:
		s.l.Fatalf(format, v...)
	case PanicLevel:
		s.l.Panicf(format, v...)
	}
}
