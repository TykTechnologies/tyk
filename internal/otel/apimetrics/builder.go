package apimetrics

import (
	"sync"

	logger "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
)

// DimensionBuilder is a compiled builder for a single instrument.
// Created at startup, immutable, safe for concurrent use.
type DimensionBuilder struct {
	extractors []*DimensionExtractor
	pool       sync.Pool
}

// NewDimensionBuilder compiles a builder from dimension definitions.
func NewDimensionBuilder(dims []DimensionDefinition) (*DimensionBuilder, error) {
	extractors := make([]*DimensionExtractor, 0, len(dims))
	for _, dim := range dims {
		ext, err := CompileExtractor(dim)
		if err != nil {
			return nil, err
		}
		extractors = append(extractors, ext)
	}

	n := len(extractors)
	if n > 10 {
		logger.Warnf("instrument has %d dimensions, exceeding SDK N<=10 fast path", n)
	}

	return &DimensionBuilder{
		extractors: extractors,
		pool: sync.Pool{
			New: func() any {
				s := make([]attribute.KeyValue, 0, n)
				return &s
			},
		},
	}, nil
}

// Build constructs an attribute KeyValue slice for one request.
// The caller must call Release with the returned pointer when done.
func (b *DimensionBuilder) Build(rc *RequestContext) (*[]attribute.KeyValue, []attribute.KeyValue) {
	ref := b.pool.Get().(*[]attribute.KeyValue) //nolint:errcheck // pool.New always returns *[]attribute.KeyValue

	for _, ext := range b.extractors {
		val := ext.Extract(rc)
		if val == "" {
			val = ext.Default
		}
		*ref = append(*ref, attribute.String(ext.Label, val))
	}

	return ref, *ref
}

// Release returns a KV slice to the pool for reuse.
func (b *DimensionBuilder) Release(ref *[]attribute.KeyValue) {
	*ref = (*ref)[:0]
	b.pool.Put(ref)
}
