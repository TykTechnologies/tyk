package logger

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// headerValue reads header or generates an uuid
func headerValue(r *http.Request, headers ...string) string {
	for _, header := range headers {
		if value := r.Header.Get(header); value != "" {
			return value
		}
	}
	return uuid.New().String()
}

type (
	requestID     struct{}
	correlationID struct{}

	requestLogger struct{}
)

// FromRequest creates a logger with request-id and correlation-id information.
// If request ID and correlation ID are not provided, they are generated.
// The logger instance is bound to the HTTP request context, and the HTTP
// Request is updated with the new context.
func FromRequest(r *http.Request) *zap.Logger {
	// Return existing logger bound in context
	ctx := r.Context()
	value, ok := ctx.Value(requestLogger{}).(*zap.Logger)
	if ok {
		return value
	}

	var (
		id  = headerValue(r, "Request-ID", "X-Request-ID")
		cid = headerValue(r, "Correlation-ID", "X-Correlation-ID")
	)

	// Add request id and correlation id to ctx
	ctx = context.WithValue(ctx, requestID{}, id)
	ctx = context.WithValue(ctx, correlationID{}, cid)

	// Create logger with context information
	logger := zap.L().With(
		zap.String("request-id", id),
		zap.String("correlation-id", cid),
	)

	// Attach logger to context
	ctx = context.WithValue(ctx, requestLogger{}, logger)

	// Update http.Request value
	*r = *(r.WithContext(ctx))

	return logger
}

func RequestID(ctx context.Context) (value string) {
	value, _ = ctx.Value(requestID{}).(string)
	return
}

func CorrelationID(ctx context.Context) (value string) {
	value, _ = ctx.Value(correlationID{}).(string)
	return
}
