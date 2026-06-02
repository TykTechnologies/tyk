package apimetrics

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

func TestDimensionBuilder_Build(t *testing.T) {
	dims := []DimensionDefinition{
		{Source: "metadata", Key: "method", Label: "http.method"},
		{Source: "metadata", Key: "response_code", Label: "status_code"},
		{Source: "header", Key: "X-Customer-ID", Label: "customer_id", Default: "unknown"},
	}

	b, err := NewDimensionBuilder(dims)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	r.Header.Set("X-Customer-ID", "cust-42")
	rc := &RequestContext{
		Request:    r,
		StatusCode: 201,
	}

	ref, kvs := b.Build(rc)
	defer b.Release(ref)

	require.Len(t, kvs, 3)
	assert.Equal(t, attribute.String("http.method", "POST"), kvs[0])
	assert.Equal(t, attribute.String("status_code", "201"), kvs[1])
	assert.Equal(t, attribute.String("customer_id", "cust-42"), kvs[2])
}

func TestDimensionBuilder_Defaults(t *testing.T) {
	dims := []DimensionDefinition{
		{Source: "header", Key: "X-Missing-Header", Label: "missing", Default: "fallback"},
		{Source: "context", Key: "tier", Label: "tier", Default: "standard"},
	}

	b, err := NewDimensionBuilder(dims)
	require.NoError(t, err)

	rc := &RequestContext{
		Request:          httptest.NewRequest(http.MethodGet, "http://example.com/", nil),
		ContextVariables: nil, // context variables not loaded
	}

	ref, kvs := b.Build(rc)
	defer b.Release(ref)

	require.Len(t, kvs, 2)
	assert.Equal(t, attribute.String("missing", "fallback"), kvs[0])
	assert.Equal(t, attribute.String("tier", "standard"), kvs[1])
}

func TestDimensionBuilder_PoolReuse(t *testing.T) {
	dims := []DimensionDefinition{
		{Source: "metadata", Key: "method", Label: "method"},
		{Source: "metadata", Key: "api_id", Label: "api_id"},
	}

	b, err := NewDimensionBuilder(dims)
	require.NoError(t, err)

	rc := &RequestContext{
		Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil),
		APIID:   "test-api",
	}

	// Run 1000 sequential Build+Release cycles to exercise pool reuse.
	for i := 0; i < 1000; i++ {
		ref, kvs := b.Build(rc)
		require.Len(t, kvs, 2, "iteration %d", i)
		assert.Equal(t, "GET", kvs[0].Value.AsString(), "iteration %d", i)
		assert.Equal(t, "test-api", kvs[1].Value.AsString(), "iteration %d", i)
		b.Release(ref)
	}
}

func TestDimensionBuilder_ConcurrentSafety(t *testing.T) {
	dims := []DimensionDefinition{
		{Source: "metadata", Key: "method", Label: "method"},
		{Source: "metadata", Key: "api_id", Label: "api_id"},
		{Source: "metadata", Key: "response_code", Label: "status_code"},
	}

	b, err := NewDimensionBuilder(dims)
	require.NoError(t, err)

	var wg sync.WaitGroup
	const goroutines = 100
	const iterations = 100

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			rc := &RequestContext{
				Request:    httptest.NewRequest(http.MethodPost, "http://example.com/", nil),
				APIID:      "concurrent-api",
				StatusCode: 200,
			}
			for i := 0; i < iterations; i++ {
				ref, kvs := b.Build(rc)
				// Verify correctness even under contention.
				if len(kvs) != 3 {
					t.Errorf("expected 3 kvs, got %d", len(kvs))
				}
				b.Release(ref)
			}
		}()
	}
	wg.Wait()
}

func TestDimensionBuilder_EmptyDimensions(t *testing.T) {
	b, err := NewDimensionBuilder(nil)
	require.NoError(t, err)

	rc := &RequestContext{
		Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil),
	}

	ref, kvs := b.Build(rc)
	assert.Empty(t, kvs)
	b.Release(ref)
}

func TestDimensionBuilder_InvalidDimension(t *testing.T) {
	dims := []DimensionDefinition{
		{Source: "unknown", Key: "foo"},
	}
	_, err := NewDimensionBuilder(dims)
	assert.Error(t, err)
}

func BenchmarkDimensionBuilder_Build(b *testing.B) {
	dims := []DimensionDefinition{
		{Source: "metadata", Key: "method", Label: "method"},
		{Source: "metadata", Key: "response_code", Label: "status_code"},
		{Source: "metadata", Key: "api_id", Label: "api_id"},
	}

	builder, err := NewDimensionBuilder(dims)
	require.NoError(b, err)

	rc := &RequestContext{
		Request:    httptest.NewRequest(http.MethodGet, "http://example.com/", nil),
		APIID:      "bench-api",
		StatusCode: 200,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ref, _ := builder.Build(rc)
		builder.Release(ref)
	}
}

func BenchmarkDimensionBuilder_Build_10Dims(b *testing.B) {
	// 10 dimensions to stay on the SDK N<=10 fast path.
	dims := []DimensionDefinition{
		{Source: "metadata", Key: "method", Label: "d1"},
		{Source: "metadata", Key: "response_code", Label: "d2"},
		{Source: "metadata", Key: "api_id", Label: "d3"},
		{Source: "metadata", Key: "api_name", Label: "d4"},
		{Source: "metadata", Key: "org_id", Label: "d5"},
		{Source: "metadata", Key: "host", Label: "d6"},
		{Source: "metadata", Key: "scheme", Label: "d7"},
		{Source: "metadata", Key: "listen_path", Label: "d8"},
		{Source: "metadata", Key: "api_version", Label: "d9"},
		{Source: "metadata", Key: "response_flag", Label: "d10"},
	}

	builder, err := NewDimensionBuilder(dims)
	require.NoError(b, err)

	rc := &RequestContext{
		Request:    httptest.NewRequest(http.MethodGet, "http://example.com/", nil),
		APIID:      "bench-api",
		APIName:    "Bench API",
		OrgID:      "org-1",
		ListenPath: "/bench",
		APIVersion: "v2",
		StatusCode: 200,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ref, _ := builder.Build(rc)
		builder.Release(ref)
	}
}
