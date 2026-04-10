package trace

import (
	"io"

	opentracing "github.com/opentracing/opentracing-go"

	"github.com/TykTechnologies/tyk/trace/jaeger"
	"github.com/TykTechnologies/tyk/trace/openzipkin"
)

// InitFunc this is a function for initializing a Tracer
type InitFunc func(name string, service string, opts map[string]interface{}, logger Logger) (Tracer, error)

type Tracer interface {
	Name() string
	opentracing.Tracer
	io.Closer
}

// NoopTracer wraps opentracing.NoopTracer to satisfy Tracer interface.
type NoopTracer struct {
	opentracing.NoopTracer
}

// Close implements io.Closer interface by doing nothing.
func (n NoopTracer) Close() error {
	return nil
}

func (n NoopTracer) Name() string {
	return "NoopTracer"
}

// Init returns a tracer for a given name.
func Init(name string, service string, opts map[string]interface{}, logger Logger) (Tracer, error) {
	switch name {
	case jaeger.Name:
		return jaeger.Init(service, opts, logger)
	case openzipkin.Name:
		return openzipkin.Init(service, opts)
	default:
		return NoopTracer{}, nil
	}
}
