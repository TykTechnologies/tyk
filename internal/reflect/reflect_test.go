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

func TestShouldOmit(t *testing.T) {
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
