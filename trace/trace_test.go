package trace

import (
	"context"
	"testing"
)

func BenchmarkNoop(b *testing.B) {
	ctx := context.WithValue(context.Background(), NoopKey{}, true)
	op := Operation(0)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		span, _ := Span(ctx, op)
		span.Finish()
	}
}
