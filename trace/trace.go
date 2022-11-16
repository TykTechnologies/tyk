package trace

import (
	"github.com/TykTechnologies/tyk/trace/otlp"
	"go.opentelemetry.io/otel/trace"
)

// InitFunc this is a function for initializing a Tracer
type InitFunc func(name string, service string, opts map[string]interface{}, logger Logger) (Tracer, error)

type Tracer interface {
	Name() string
	trace.Tracer
}

// Init returns a tracer for a given name.
func Init(name string, service string, opts map[string]interface{}, logger Logger) (Tracer, error) {
	switch name {
	default:
		return otlp.Init(service, opts, logger)
	}
}
