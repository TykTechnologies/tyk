package trace

import (
	"testing"
)

type testTracer struct {
	NoopTracer
	closed bool
	name   string
}

func (t *testTracer) Close() error {
	t.closed = true
	return nil
}
func (t *testTracer) Name() string {
	return t.name
}

func TestOpenTracer(t *testing.T) {
	// t.Run("sets and activate a global opnentracer", func(ts *testing.T) {
	// 	o := NewManager(nil)
	// 	tr := &testTracer{name: "set-tracer"}
	// 	o.Set(tr)
	// 	active := o.Get()
	// 	if active == nil {
	// 		ts.Fatal("expected active tracer")
	// 	}
	// 	if active.Name() != tr.Name() {
	// 		ts.Errorf("expected %s got %s", tr.Name(), active.Name())
	// 	}
	// 	global := opentracing.GlobalTracer()
	// 	if global == nil {
	// 		ts.Fatal("expected global tracer")
	// 	}
	// 	active, ok := global.(Tracer)
	// 	if !ok {
	// 		ts.Fatal("expected global tracer to implement Tracer")
	// 	}
	// 	if active.Name() != tr.Name() {
	// 		ts.Errorf("expected %s got %s", tr.Name(), active.Name())
	// 	}
	// })

	// t.Run("closes active tracer before setting new one", func(ts *testing.T) {
	// 	o := NewManager(nil)
	// 	tr := &testTracer{name: "set-tracer"}
	// 	o.Set(tr)
	// 	o.Set(&testTracer{name: "new-test"})
	// 	if !tr.closed {
	// 		ts.Error("expected this tracer to be closed")
	// 	}
	// })
}
