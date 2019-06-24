package trace

import (
	"io"

	"github.com/TykTechnologies/tyk/trace/jaeger"
	"github.com/opentracing/opentracing-go"
)

type Tracer interface {
	Name() string
	opentracing.Tracer
	io.Closer
	TraceIDHeader() string
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

func (n NoopTracer) TraceIDHeader() string {
	return ""
}

// Init returns a tracer for a given name.
func Init(name string, service string, opts map[string]interface{}, logger Logger) (Tracer, error) {
	switch name {
	case jaeger.Name:
		return jaeger.Init(service, opts, logger)
	default:
		return NoopTracer{}, nil
	}
}
