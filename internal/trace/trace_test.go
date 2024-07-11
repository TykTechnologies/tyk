package trace

import "testing"

func TestInit(t *testing.T) {
	t.Run("returns noop tracer when no match", func(ts *testing.T) {
		o, err := Init("noop", "noop", nil, nil)
		if err != nil {
			ts.Fatal("expected err to be nil")
		}
		_ = o.(NoopTracer)
	})
}
