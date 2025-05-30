package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testStruct struct {
	Bool      bool
	Array     []string
	Map       map[string]string
	SubStruct *subStruct
	BoolPtr   *bool
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
	v7 := testStruct{Array: make([]string, 0), Map: make(map[string]string), SubStruct: &subStruct{SubMap: make(map[string]string)}, BoolPtr: boolPtr(false)}
	v8 := testStruct{Array: make([]string, 0), Map: make(map[string]string), SubStruct: &subStruct{SubMap: make(map[string]string)}, BoolPtr: boolPtr(true)}

	assert.True(t, ShouldOmit(v1))
	assert.True(t, ShouldOmit(v2))
	assert.True(t, ShouldOmit(v3))
	assert.False(t, ShouldOmit(v4))
	assert.False(t, ShouldOmit(v5))
	assert.False(t, ShouldOmit(v6))
	assert.False(t, ShouldOmit(v7))
	assert.False(t, ShouldOmit(v8))
}

func boolPtr(v bool) *bool {
	return &v
}
