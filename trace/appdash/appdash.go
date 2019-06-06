package appdash

import (
	"errors"
	"time"

	"github.com/opentracing/opentracing-go"
	"sourcegraph.com/sourcegraph/appdash"
	dash "sourcegraph.com/sourcegraph/appdash/opentracing"
)

// Name is the name of this tracer.
const Name = "appdash"

// Trace implemants tyk trace.Tracer interface.
type Trace struct {
	opentracing.Tracer
	cc *appdash.ChunkedCollector
}

// Init returns a Trace instance. This requires conn key be present in opts. It
// is a url to connect to the appdash server.
func Init(opts map[string]string) (Trace, error) {
	conn, ok := opts["conn"]
	if !ok {
		return Trace{}, errors.New("missing conn option")
	}
	rc := appdash.NewRemoteCollector(conn)
	cc := &appdash.ChunkedCollector{
		Collector:   rc,
		MinInterval: time.Millisecond,
	}
	return Trace{
		Tracer: dash.NewTracer(cc),
		cc:     cc,
	}, nil
}

// Close stops the underlying appdash collector.
func (tr Trace) Close() error {
	tr.cc.Stop()
	return nil
}

// Name returns the name of this tracer
func (tr Trace) Name() string {
	return Name
}
