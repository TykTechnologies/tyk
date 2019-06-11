package jaeger

import (
	"io"

	"github.com/opentracing/opentracing-go"
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

// Init returns a implementation of tyk.Tracer using jaeger client.
func Init(opts map[string]interface{}) (*Trace, error) {
	cfg, err := Load(opts)
	tr, cls, err := cfg.NewTracer()
	if err != nil {
		return nil, err
	}
	return &Trace{Tracer: tr, Closer: cls}, nil
}
