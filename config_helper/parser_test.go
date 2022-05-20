package config_helper

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestStruct struct {
	Exported    string
	notExported bool

	StrField struct {
		Test  string
		Other struct {
			OtherTest  bool
			nonEmbeded string
		}
	}

	JsonExported int `json:"name"`
}

func TestParseEnvsValues(t *testing.T) {

	tcs := []struct {
		testName     string
		testStruct   interface{}
		expectedLen  int
		expectedEnvs []string
	}{
		{
			testName: "KEY:VALUE common struct",
			testStruct: struct {
				Key string
			}{
				Key: "Value",
			},
			expectedLen:  1,
			expectedEnvs: []string{"KEY:Value"},
		},
		{
			testName: "KEY:VALUE with json tag",
			testStruct: struct {
				Key string `json:"json_name"`
			}{
				Key: "Value",
			},
			expectedLen:  1,
			expectedEnvs: []string{"JSONNAME:Value"},
		},
		{
			testName: "KEY:VALUE with json tag and omitempty",
			testStruct: struct {
				Key string `json:"json_name,omitempty"`
			}{
				Key: "Value",
			},
			expectedLen:  1,
			expectedEnvs: []string{"JSONNAME:Value"},
		},
		{
			testName: "KEY:VALUE with json '-' tag",
			testStruct: struct {
				Key string `json:"-"`
			}{
				Key: "Value",
			},
			expectedLen:  1,
			expectedEnvs: []string{"KEY:Value"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.testName, func(t *testing.T) {
			helper := New(tc.testStruct, "")
			envs := helper.ParseEnvs()

			assert.Len(t, envs, tc.expectedLen)
			assert.EqualValues(t, tc.expectedEnvs, envs)
		})
	}

}

func TestParseEnvsLen(t *testing.T) {
	var testStruct = TestStruct{
		Exported:    "val1",
		notExported: true,

		StrField: struct {
			Test  string
			Other struct {
				OtherTest  bool
				nonEmbeded string
			}
		}{Test: "test"},
		JsonExported: 5,
	}
	helper := New(testStruct, "TYK_")

	envs := helper.ParseEnvs()

	assert.Len(t, envs, 4)
}

func TestParseEnvsPrefix(t *testing.T) {
	var testStruct = TestStruct{
		Exported:    "val1",
		notExported: true,

		StrField: struct {
			Test  string
			Other struct {
				OtherTest  bool
				nonEmbeded string
			}
		}{Test: "test"},
		JsonExported: 5,
	}

	prefix := "TYK_TEST_"
	helper := New(testStruct, prefix)

	envs := helper.ParseEnvs()

	for _, env := range envs {
		assert.True(t, strings.HasPrefix(env, prefix))
	}
}
