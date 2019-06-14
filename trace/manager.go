package trace

import (
	"sync"

	"github.com/opentracing/opentracing-go"
)

// Logger defines api for logging messages by the OpenTracer struct. This is a
// workaround to avoid trying this to logrus
type Logger interface {
	Errorf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
}

// OpenTracer sets opentracing for the gateway. This supports updating active
// tracer on the fly without the need to restart the application.
type OpenTracer struct {
	mu     sync.RWMutex
	tracer Tracer
	log    Logger
}

// NewManager returns a new opentrace manager. If log is not nil it will be used
// to log errors and info by the manager.
func NewManager(log Logger) *OpenTracer {
	return &OpenTracer{log: log}
}

//Get returns active tracer or nil
func (o *OpenTracer) Get() Tracer {
	o.mu.RLock()
	t := o.tracer
	o.mu.RUnlock()
	return t
}

// Set makes tr the active tracer. This calls opentracing.SetGlobalTracer making
// tr the global tracer.
//
// If there was another running tracer it will be closed.
func (o *OpenTracer) Set(tr Tracer) {
	if err := o.Close(); err != nil {
		if o.log != nil {
			o.log.Errorf("closing tracer %v\n", err)
		}
	}
	o.mu.Lock()
	if o.log != nil {
		o.log.Infof("activate tracer: %s\n", tr.Name())
	}
	o.tracer = tr
	opentracing.SetGlobalTracer(tr)
	o.mu.Unlock()
}

// Close calls Close on the active tracer.
func (o *OpenTracer) Close() error {
	if t := o.Get(); t != nil {
		return t.Close()
	}
	return nil
}

// SetupTracing uses cfg to create and initialize a new opentracer. If there was
// already a tracer running it will be closed before the new one is set. This is
// safe to use concurrently.
func (o *OpenTracer) SetupTracing(name string, opts map[string]interface{}) {
	tr, err := Init(name, opts, o.log)
	if err != nil {
		if o.log != nil {
			o.log.Errorf("initializing tracer %s err=%v\n", name, err)
		}
		return
	}
	if _, ok := tr.(NoopTracer); ok {
		if o.log != nil {
			o.log.Infof("tracer: %s was not found using NoOpTracer instead\n", name)
		}
	}
	o.Set(tr)
}
