package oas

import (
	"reflect"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/errors"
	"github.com/stretchr/testify/assert"
)

func TestErrorOverridesMap_FillAndExtract(t *testing.T) {
	internalMatch := &apidef.ErrorMatcher{
		Flag:           errors.TLE,
		MessagePattern: ".*error.*",
		BodyField:      "status",
		BodyValue:      "fail",
	}

	internalResponse := apidef.ErrorResponse{
		StatusCode: 503,
		Body:       "{\"error\": \"offline\"}",
		Headers:    map[string]string{"X-Tyk-Override": "true"},
	}

	tests := []struct {
		name      string
		input     apidef.ErrorOverridesMap
		expectNil bool
	}{
		{
			name: "Happy path: Full mapping",
			input: apidef.ErrorOverridesMap{
				"500": {
					{Match: internalMatch, Response: internalResponse},
				},
			},
			expectNil: false,
		},
		{
			name: "Multiple status codes",
			input: apidef.ErrorOverridesMap{
				"401": {{Response: apidef.ErrorResponse{StatusCode: 403}}},
				"404": {{Response: apidef.ErrorResponse{StatusCode: 410}}},
			},
			expectNil: false,
		},
		{
			name:      "Empty input map",
			input:     apidef.ErrorOverridesMap{},
			expectNil: true,
		},
		{
			name:      "Nil input map",
			input:     nil,
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := apidef.APIDefinition{ErrorOverrides: tt.input}
			var oasMap ErrorOverridesMap
			oasMap.Fill(api)

			if tt.expectNil {
				assert.Nil(t, oasMap)
				return
			}

			resultApi := &apidef.APIDefinition{}
			oasMap.ExtractTo(resultApi)

			if !reflect.DeepEqual(tt.input, resultApi.ErrorOverrides) {
				t.Errorf("Round-trip failed.\nExpected: %+v\nGot: %+v", tt.input, resultApi.ErrorOverrides)
			}
		})
	}
}

func TestErrorOverridesMap_NilSafety(t *testing.T) {
	t.Run("ExtractTo with nil receiver", func(t *testing.T) {
		var nilMap ErrorOverridesMap
		api := &apidef.APIDefinition{}

		nilMap.ExtractTo(api)
		assert.Nil(
			t,
			api.ErrorOverrides,
			"ExtractTo should not have initialized internal map from a nil receiver",
		)
	})

	t.Run("Fill into nil map pointer", func(t *testing.T) {
		var m ErrorOverridesMap
		api := apidef.APIDefinition{
			ErrorOverrides: apidef.ErrorOverridesMap{
				"500": {{Response: apidef.ErrorResponse{StatusCode: 500}}},
			},
		}

		(&m).Fill(api)
		assert.NotNil(t, m)
	})
}
