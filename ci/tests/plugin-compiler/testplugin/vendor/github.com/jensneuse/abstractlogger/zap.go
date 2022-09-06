package abstractlogger

import (
	"go.uber.org/zap"
)

func NewZapLogger(zapLogger *zap.Logger, level Level) *ZapLogger {
	return &ZapLogger{
		l:          zapLogger,
		levelCheck: NewLevelCheck(level),
	}
}

// ZapLogger implements the Logging frontend using the popular logging backend zap
// It uses the LevelCheck helper to increase performance.
type ZapLogger struct {
	l          *zap.Logger
	levelCheck LevelCheck
}

func (z *ZapLogger) LevelLogger(level Level) LevelLogger {
	return &ZapLevelLogger{
		l:     z.l.Sugar(),
		level: level,
	}
}

func (z *ZapLogger) field(field Field) zap.Field {
	switch field.kind {
	case StringField:
		return zap.String(field.key, field.stringValue)
	case IntField:
		return zap.Int(field.key, int(field.intValue))
	case BoolField:
		return zap.Bool(field.key, field.intValue != 0)
	case ByteStringField:
		return zap.ByteString(field.key, field.byteValue)
	case ErrorField:
		return zap.Error(field.errorValue)
	case NamedErrorField:
		return zap.NamedError(field.key, field.errorValue)
	case StringsField:
		return zap.Strings(field.key, field.stringsValue)
	default:
		return zap.Any(field.key, field.interfaceValue)
	}
}

func (z *ZapLogger) fields(fields []Field) []zap.Field {
	out := make([]zap.Field, len(fields))
	for i := range fields {
		out[i] = z.field(fields[i])
	}
	return out
}

func (z *ZapLogger) Debug(msg string, fields ...Field) {
	if !z.levelCheck.Check(DebugLevel) {
		return
	}
	z.l.Debug(msg, z.fields(fields)...)
}

func (z *ZapLogger) Info(msg string, fields ...Field) {
	if !z.levelCheck.Check(InfoLevel) {
		return
	}
	z.l.Info(msg, z.fields(fields)...)
}

func (z *ZapLogger) Warn(msg string, fields ...Field) {
	if !z.levelCheck.Check(WarnLevel) {
		return
	}
	z.l.Warn(msg, z.fields(fields)...)
}

func (z *ZapLogger) Error(msg string, fields ...Field) {
	if !z.levelCheck.Check(ErrorLevel) {
		return
	}
	z.l.Error(msg, z.fields(fields)...)
}

func (z *ZapLogger) Fatal(msg string, fields ...Field) {
	if !z.levelCheck.Check(FatalLevel) {
		return
	}
	z.l.Fatal(msg, z.fields(fields)...)
}

func (z *ZapLogger) Panic(msg string, fields ...Field) {
	if !z.levelCheck.Check(PanicLevel) {
		return
	}
	z.l.Panic(msg, z.fields(fields)...)
}

type ZapLevelLogger struct {
	l     *zap.SugaredLogger
	level Level
}

func (z *ZapLevelLogger) Println(v ...interface{}) {
	switch z.level {
	case DebugLevel:
		z.l.Debug(v...)
	case InfoLevel:
		z.l.Info(v...)
	case WarnLevel:
		z.l.Warn(v...)
	case ErrorLevel:
		z.l.Error(v...)
	case FatalLevel:
		z.l.Fatal(v...)
	case PanicLevel:
		z.l.Panic(v...)
	}
}

func (z *ZapLevelLogger) Printf(format string, v ...interface{}) {
	switch z.level {
	case DebugLevel:
		z.l.Debugf(format, v...)
	case InfoLevel:
		z.l.Infof(format, v...)
	case WarnLevel:
		z.l.Warnf(format, v...)
	case ErrorLevel:
		z.l.Errorf(format, v...)
	case FatalLevel:
		z.l.Fatalf(format, v...)
	case PanicLevel:
		z.l.Panicf(format, v...)
	}
}
