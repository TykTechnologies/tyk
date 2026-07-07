package config

import "github.com/sirupsen/logrus"

type kvLogger struct{ l *logrus.Logger }

func (a kvLogger) Warn(msg string, fields map[string]any) { a.l.WithFields(fields).Warn(msg) }
func (a kvLogger) Warnf(format string, args ...any)       { a.l.Warnf(format, args...) }
