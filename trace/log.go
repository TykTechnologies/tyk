package trace

import (
	"context"
	"fmt"

	opentracing "github.com/opentracing/opentracing-go"
	opentracinglog "github.com/opentracing/opentracing-go/log"
)

// Logrus implements a subset of logrus api to reduce friction when we want
// to log both on opentracing and on logrus.
type Logrus interface {
	Debug(args ...interface{})
	Error(args ...interface{})
	Warning(args ...interface{})
	Info(args ...interface{})
}

// Debug creates debug log on both logrus and span.
// SW-REQ-165
func Debug(ctx context.Context, logrus Logrus, args ...interface{}) {
	logrus.Debug(args...)
	Log(ctx, opentracinglog.String("DEBUG", fmt.Sprint(args...)))
}

// SW-REQ-165
func Error(ctx context.Context, logrus Logrus, args ...interface{}) {
	logrus.Error(args...)
	Log(ctx, opentracinglog.String("ERROR", fmt.Sprint(args...)))
}

// SW-REQ-165
func Warning(ctx context.Context, logrus Logrus, args ...interface{}) {
	logrus.Warning(args...)
	Log(ctx, opentracinglog.String("WARN", fmt.Sprint(args...)))
}

// Log tries to check if there is a span in ctx and adds logs fields on the span.
// SW-REQ-165
func Log(ctx context.Context, fields ...opentracinglog.Field) {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span.LogFields(fields...)
	}
}

// SW-REQ-165
func Info(ctx context.Context, logrus Logrus, args ...interface{}) {
	logrus.Info(args...)
	Log(ctx, opentracinglog.String("INFO", fmt.Sprint(args...)))
}
