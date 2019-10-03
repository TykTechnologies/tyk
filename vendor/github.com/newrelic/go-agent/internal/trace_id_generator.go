package internal

import (
	"fmt"
	"math/rand"
	"sync"
)

// TraceIDGenerator creates identifiers for distributed tracing.
type TraceIDGenerator struct {
	sync.Mutex
	rnd *rand.Rand
}

// NewTraceIDGenerator creates a new trace identifier generator.
func NewTraceIDGenerator(seed int64) *TraceIDGenerator {
	return &TraceIDGenerator{
		rnd: rand.New(rand.NewSource(seed)),
	}
}

// GenerateTraceID creates a new trace identifier.
func (tg *TraceIDGenerator) GenerateTraceID() string {
	tg.Lock()
	defer tg.Unlock()

	u1 := tg.rnd.Uint32()
	u2 := tg.rnd.Uint32()
	bits := (uint64(u1) << 32) | uint64(u2)
	return fmt.Sprintf("%016x", bits)
}
