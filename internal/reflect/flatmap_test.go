package reflect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_InvalidMapKey(t *testing.T) {
	type testStruct struct{}
	testStructVal := testStruct{}

	val := map[string]interface{}{
		"key": map[testStruct]string{
			testStructVal: "Hello",
		},
	}

	_, err := Flatten(val)
	assert.Error(t, err)
}

func Test_Flatten(t *testing.T) {
	type subStruct struct {
		SubMap map[string]string
	}
	type testStruct struct {
		Bool      bool
		Array     []string
		Map       map[string]interface{}
		SubStruct *subStruct
	}

	input := map[string]interface{}{
		"v1": testStruct{},
		"v2": testStruct{Array: make([]string, 0), Map: make(map[string]interface{}), SubStruct: &subStruct{}},
		"v3": testStruct{Array: make([]string, 0), Map: make(map[string]interface{}), SubStruct: &subStruct{SubMap: make(map[string]string)}},
		"v4": testStruct{Bool: true},
		"v5": testStruct{Array: []string{"a"}},
		"v6": testStruct{
			Map: map[string]interface{}{
				"a": "b",
				"b": uint64(123),
				"c": int64(123),
				"d": float64(123.0),
				"e": struct{ Testing string }{"testing"},
				"f": func() {},
				"g": [2]string{"yes", "no"},
			},
		},
	}

	want := FlatMap{
		"v1.Bool":          "false",
		"v2.Bool":          "false",
		"v3.Bool":          "false",
		"v4.Bool":          "true",
		"v5.Bool":          "false",
		"v5.Array.0":       "a",
		"v6.Bool":          "false",
		"v6.Map.a":         "b",
		"v6.Map.b":         "123",
		"v6.Map.c":         "123",
		"v6.Map.d":         "123.000000",
		"v6.Map.e.Testing": "testing",
		"v6.Map.g.0":       "yes",
		"v6.Map.g.1":       "no",
	}

	got, err := Flatten(input)
	assert.NoError(t, err)
	assert.Equal(t, got, want)
}
