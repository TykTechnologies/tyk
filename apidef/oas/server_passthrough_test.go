package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestRequestBodyPassthrough(t *testing.T) {
	t.Run("fill", func(t *testing.T) {
		type testCase struct {
			title    string
			input    apidef.APIDefinition
			expected *RequestBodyPassthrough
		}

		testCases := []testCase{
			{
				title: "not enabled",
				input: apidef.APIDefinition{
					EnableRequestBodyPassthrough: false,
				},
				expected: nil,
			},
			{
				title: "enabled",
				input: apidef.APIDefinition{
					EnableRequestBodyPassthrough: true,
				},
				expected: &RequestBodyPassthrough{
					Enabled: true,
				},
			},
		}

		for _, tc := range testCases {
			tc := tc
			t.Run(tc.title, func(t *testing.T) {
				t.Parallel()

				server := new(Server)
				server.Fill(tc.input)

				assert.Equal(t, tc.expected, server.RequestBodyPassthrough)
			})
		}
	})

	t.Run("extractTo", func(t *testing.T) {
		type testCase struct {
			title    string
			input    *RequestBodyPassthrough
			expected apidef.APIDefinition
		}

		testCases := []testCase{
			{
				title: "not enabled",
				input: &RequestBodyPassthrough{
					Enabled: false,
				},
				expected: apidef.APIDefinition{
					EnableRequestBodyPassthrough: false,
				},
			},
			{
				title: "enabled",
				input: &RequestBodyPassthrough{
					Enabled: true,
				},
				expected: apidef.APIDefinition{
					EnableRequestBodyPassthrough: true,
				},
			},
		}

		for _, tc := range testCases {
			tc := tc
			t.Run(tc.title, func(t *testing.T) {
				t.Parallel()

				var apiDef apidef.APIDefinition
				tc.input.ExtractTo(&apiDef)

				assert.Equal(t, tc.expected, apiDef)
			})
		}
	})
}
