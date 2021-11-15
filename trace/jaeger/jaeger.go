package jaeger

import (
	"io"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/uber/jaeger-client-go/config"
)

// Name is the name of this tracer.
const Name = "jaeger"

type Trace struct {
	opentracing.Tracer
	io.Closer
}

func (Trace) Name() string {
	return Name
}

type Logger interface {
	Errorf(msg string, args ...interface{})
	Infof(msg string, args ...interface{})
}

type wrapLogger struct {
	Logger
}

func (w wrapLogger) Error(msg string) {
	w.Errorf("%s", msg)
}

// Init returns a implementation of tyk.Tracer using jaeger client.
func Init(service string, opts map[string]interface{}, log Logger) (*Trace, error) {
	cfg, _ := Load(opts)
	if service != "" {
		cfg.ServiceName = service
	}
	tr, cls, err := cfg.NewTracer(
		config.Logger(&wrapLogger{Logger: log}),
	)
	if err != nil {
		return nil, err
	}
	return &Trace{Tracer: tr, Closer: cls}, nil
}
