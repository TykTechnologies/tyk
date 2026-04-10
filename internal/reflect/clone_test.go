package reflect_test

import (
	"encoding/json"
	"testing"

	"github.com/TykTechnologies/tyk/internal/reflect"
)

// cloneJSON performs cloning using JSON marshalling and unmarshalling.
func cloneJSON[T any](t T) T {
	data, err := json.Marshal(t)
	if err != nil {
		panic(err) // Should not happen in a benchmark test
	}
	var copy T
	if err := json.Unmarshal(data, &copy); err != nil {
		panic(err) // Should not happen in a benchmark test
	}
	return copy
}

// Sample struct to test cloning performance.
type SampleStruct struct {
	Name  string
	Age   int
	Email string
	Tags  []string
}

// Benchmark for reflect.Clone
func BenchmarkReflectClone(b *testing.B) {
	sample := SampleStruct{
		Name:  "John Doe",
		Age:   30,
		Email: "john.doe@example.com",
		Tags:  []string{"golang", "performance", "benchmark"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reflect.Clone(sample)
	}
}

// Benchmark for JSON-based cloning
func BenchmarkJSONClone(b *testing.B) {
	sample := SampleStruct{
		Name:  "John Doe",
		Age:   30,
		Email: "john.doe@example.com",
		Tags:  []string{"golang", "performance", "benchmark"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cloneJSON(sample)
	}
}
