package reflect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IsZero(t *testing.T) {
	type testStruct struct {
		Name string
	}

	zeroes := []interface{}{
		false,
		0,
		0.0,
		[1]string{""},
		(*testStruct)(nil),
		(func())(nil),
		"",
		testStruct{},
	}

	for _, zero := range zeroes {
		assert.True(t, IsEmpty(zero))
	}
}

func Test_IsEmpty(t *testing.T) {
	type subStruct struct {
		SubMap map[string]string
	}
	type testStruct struct {
		Bool      bool
		Array     []string
		Map       map[string]string
		SubStruct *subStruct
	}

	testcases := []struct {
		input testStruct
		want  bool
	}{
		{
			input: testStruct{},
			want:  true,
		},
		{
			input: testStruct{Array: make([]string, 0), Map: make(map[string]string), SubStruct: &subStruct{}},
			want:  true,
		},
		{
			input: testStruct{Array: make([]string, 0), Map: make(map[string]string), SubStruct: &subStruct{SubMap: make(map[string]string)}},
			want:  true,
		},
		{
			input: testStruct{Bool: true},
		},
		{
			input: testStruct{Array: []string{"a"}},
		},
		{
			input: testStruct{Map: map[string]string{"a": "b"}},
		},
	}

	for _, testcase := range testcases {
		got := IsEmpty(testcase.input)
		assert.Equal(t, got, testcase.want)
	}
}
