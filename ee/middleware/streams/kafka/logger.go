package kafka

import (
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/warpstreamlabs/bento/public/service"
)

type kgoLogger struct {
	l *service.Logger
}

func (k *kgoLogger) Level() kgo.LogLevel {
	return kgo.LogLevelDebug
}

func (k *kgoLogger) Log(level kgo.LogLevel, msg string, keyvals ...any) {
	tmpL := k.l
	if len(keyvals) > 0 {
		tmpL = k.l.With(keyvals...)
	}

	switch level {
	case kgo.LogLevelError:
		tmpL.Error(msg)
	case kgo.LogLevelWarn:
		tmpL.Warn(msg)
	case kgo.LogLevelInfo:
		tmpL.Debug(msg)
	case kgo.LogLevelDebug:
		tmpL.Trace(msg)
	}
}
