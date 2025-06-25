package reflect_test

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
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

func ptr[T any](val T) *T {
	return &val
}

func TestReflectClone(t *testing.T) {
	type dummyStruct struct {
		ptr           *string
		sliceOfPtr    []*string
		mapOfPtrOfPtr map[string]*int
	}

	base := &dummyStruct{
		ptr: ptr("ptr"),
		sliceOfPtr: []*string{
			ptr("a"),
			ptr("b"),
			ptr("c"),
		},
		mapOfPtrOfPtr: map[string]*int{
			"one": ptr(1),
			"two": ptr(2),
		},
	}

	clone := reflect.Clone(base)

	assert.Equal(t, base, clone)
	assert.Equal(t, len(base.sliceOfPtr), len(clone.sliceOfPtr))
	assert.Equal(t, len(base.mapOfPtrOfPtr), len(clone.mapOfPtrOfPtr))

	assert.NotSame(t, base.ptr, clone.ptr)

	for i := 0; i < len(base.sliceOfPtr); i++ {
		assert.Equal(t, base.sliceOfPtr[i], clone.sliceOfPtr[i])
		assert.NotSame(t, base.sliceOfPtr[i], clone.sliceOfPtr[i])
	}

	for key := range base.mapOfPtrOfPtr {
		var eBase = base.mapOfPtrOfPtr[key]
		var eClone = clone.mapOfPtrOfPtr[key]
		assert.Equal(t, eBase, eClone)
		assert.NotSame(t, eBase, eClone)
	}
}
