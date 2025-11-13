package reflect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testStruct struct {
	Bool      bool
	Array     []string
	Map       map[string]string
	SubStruct *subStruct
}

type subStruct struct {
	SubMap map[string]string
}

func Test_IsEmpty(t *testing.T) {
	v1 := testStruct{}
	v2 := testStruct{Array: make([]string, 0), Map: make(map[string]string), SubStruct: &subStruct{}}
	v3 := testStruct{Array: make([]string, 0), Map: make(map[string]string), SubStruct: &subStruct{SubMap: make(map[string]string)}}
	v4 := testStruct{Bool: true}
	v5 := testStruct{Array: []string{"a"}}
	v6 := testStruct{Map: map[string]string{"a": "b"}}

	assert.True(t, IsEmpty(v1))
	assert.True(t, IsEmpty(v2))
	assert.True(t, IsEmpty(v3))
	assert.False(t, IsEmpty(v4))
	assert.False(t, IsEmpty(v5))
	assert.False(t, IsEmpty(v6))
}

func Test_Cast(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		result, err := Cast[int](2)
		assert.NoError(t, err)
		assert.Equal(t, 2, *result)
	})

	t.Run("float64", func(t *testing.T) {
		result, err := Cast[float64](2.0)
		assert.NoError(t, err)
		assert.Equal(t, 2.0, *result)
	})

	t.Run("string", func(t *testing.T) {
		result, err := Cast[string]("string")
		assert.NoError(t, err)
		assert.Equal(t, "string", *result)
	})

	t.Run("struct", func(t *testing.T) {
		type A struct{ Name string }
		result, err := Cast[map[string]interface{}](A{Name: "Alice"})
		assert.NoError(t, err)
		assert.Equal(t, map[string]interface{}{"Name": "Alice"}, *result)
	})

	t.Run("slice", func(t *testing.T) {
		result, err := Cast[[]float64]([]int{10, 20})
		assert.NoError(t, err)
		assert.Equal(t, []float64{10.0, 20.0}, *result)
	})

	t.Run("channel", func(t *testing.T) {
		_, err := Cast[map[string]interface{}](make(chan int))
		assert.Error(t, err)
	})

	t.Run("function", func(t *testing.T) {
		_, err := Cast[map[string]interface{}](func() {})
		assert.Error(t, err)
	})
}
