package trace

import (
	"context"
	"fmt"

	"github.com/opentracing/opentracing-go/log"
)

// Logrus implements a subset of logrus api to reduce friction when we want
// to log both on opentracing and on logrus.
type Logrus interface {
	Debug(args ...interface{})
	Error(args ...interface{})
	Warning(args ...interface{})
}

// Debug creates debug log on both logrus and span.
func Debug(ctx context.Context, logrus Logrus, args ...interface{}) {
	logrus.Debug(args...)
	Log(ctx, log.String("DEBUG", fmt.Sprint(args...)))
}

func Error(ctx context.Context, logrus Logrus, args ...interface{}) {
	logrus.Error(args...)
	Log(ctx, log.String("ERROR", fmt.Sprint(args...)))
}

func Warning(ctx context.Context, logrus Logrus, args ...interface{}) {
	logrus.Warning(args...)
	Log(ctx, log.String("WARN", fmt.Sprint(args...)))
}
