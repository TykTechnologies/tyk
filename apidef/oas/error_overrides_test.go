package oas

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/errors"
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
		Message:    "Service offline",
		Template:   "offline.html",
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
				"401": {{Response: apidef.ErrorResponse{StatusCode: 403, Body: "Forbidden"}}},
				"404": {{Response: apidef.ErrorResponse{StatusCode: 410, Body: "Gone"}}},
			},
			expectNil: false,
		},
		{
			name: "Multiple overrides per status code",
			input: apidef.ErrorOverridesMap{
				"500": {
					{
						Match:    &apidef.ErrorMatcher{Flag: errors.TLE},
						Response: apidef.ErrorResponse{StatusCode: 503, Body: "TLE Error"},
					},
					{
						Match:    &apidef.ErrorMatcher{Flag: "timeout"},
						Response: apidef.ErrorResponse{StatusCode: 504, Body: "Timeout Error"},
					},
				},
			},
			expectNil: false,
		},
		{
			name: "Override without match",
			input: apidef.ErrorOverridesMap{
				"502": {
					{
						Match:    nil,
						Response: apidef.ErrorResponse{StatusCode: 502, Body: "Bad Gateway"},
					},
				},
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

			assert.NotNil(t, oasMap)

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
				"500": {{Response: apidef.ErrorResponse{StatusCode: 500, Body: "Internal Error"}}},
			},
		}

		(&m).Fill(api)
		assert.NotNil(t, m)
		assert.Len(t, m, 1)
		assert.Len(t, m["500"], 1)
		assert.Equal(t, 500, m["500"][0].Response.StatusCode)
		assert.Equal(t, "Internal Error", m["500"][0].Response.Body)
	})
}

func TestErrorOverride_FillAndExtract(t *testing.T) {
	tests := []struct {
		name  string
		input apidef.ErrorOverride
	}{
		{
			name: "Complete error override with match",
			input: apidef.ErrorOverride{
				Match: &apidef.ErrorMatcher{
					Flag:           errors.TLE,
					MessagePattern: ".*timeout.*",
					BodyField:      "error.type",
					BodyValue:      "TIMEOUT",
				},
				Response: apidef.ErrorResponse{
					StatusCode: 504,
					Body:       "{\"error\": \"Gateway timeout\"}",
					Message:    "Request timed out",
					Template:   "timeout.html",
					Headers: map[string]string{
						"X-Error-Type": "TIMEOUT",
						"Retry-After":  "30",
					},
				},
			},
		},
		{
			name: "Error override without match",
			input: apidef.ErrorOverride{
				Match: nil,
				Response: apidef.ErrorResponse{
					StatusCode: 500,
					Body:       "{\"error\": \"Internal server error\"}",
					Message:    "Something went wrong",
					Template:   "error.html",
					Headers: map[string]string{
						"X-Error-Source": "GATEWAY",
					},
				},
			},
		},
		{
			name: "Minimal error override",
			input: apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					StatusCode: 403,
				},
			},
		},
		{
			name: "Error override with empty headers",
			input: apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					StatusCode: 401,
					Body:       "{\"error\": \"Unauthorized\"}",
					Headers:    map[string]string{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var oasOverride ErrorOverride
			oasOverride.Fill(tt.input)

			var extracted apidef.ErrorOverride
			oasOverride.ExtractTo(&extracted)

			if !reflect.DeepEqual(tt.input, extracted) {
				t.Errorf("Round-trip failed. Expected: %+v Got: %+v", tt.input, extracted)
			}
		})
	}
}

func TestErrorMatcher_ExtractTo(t *testing.T) {
	tests := []struct {
		name  string
		input ErrorMatcher
	}{
		{
			name: "Complete error matcher",
			input: ErrorMatcher{
				Flag:           errors.TLE,
				MessagePattern: ".*error.*",
				BodyField:      "status.code",
				BodyValue:      "ERROR",
			},
		},
		{
			name: "Minimal error matcher",
			input: ErrorMatcher{
				Flag: "custom_flag",
			},
		},
		{
			name:  "Empty error matcher",
			input: ErrorMatcher{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var extracted apidef.ErrorMatcher
			tt.input.ExtractTo(&extracted)

			assert.Equal(t, tt.input.Flag, extracted.Flag)
			assert.Equal(t, tt.input.MessagePattern, extracted.MessagePattern)
			assert.Equal(t, tt.input.BodyField, extracted.BodyField)
			assert.Equal(t, tt.input.BodyValue, extracted.BodyValue)
		})
	}
}

func TestErrorResponse_ExtractTo(t *testing.T) {
	tests := []struct {
		name  string
		input ErrorResponse
	}{
		{
			name: "Complete error response",
			input: ErrorResponse{
				StatusCode: 500,
				Body:       "{\"error\": \"server error\"}",
				Message:    "Internal server error occurred",
				Template:   "error.html",
				Headers: map[string]string{
					"X-Error-Code": "500",
					"Retry-After":  "60",
				},
			},
		},
		{
			name: "Minimal error response",
			input: ErrorResponse{
				StatusCode: 404,
			},
		},
		{
			name: "Error response with empty headers",
			input: ErrorResponse{
				StatusCode: 403,
				Body:       "{\"error\": \"forbidden\"}",
				Headers:    map[string]string{},
			},
		},
		{
			name: "Error response with nil headers",
			input: ErrorResponse{
				StatusCode: 401,
				Body:       "{\"error\": \"unauthorized\"}",
				Headers:    nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var extracted apidef.ErrorResponse
			tt.input.ExtractTo(&extracted)

			assert.Equal(t, tt.input.StatusCode, extracted.StatusCode)
			assert.Equal(t, tt.input.Body, extracted.Body)
			assert.Equal(t, tt.input.Message, extracted.Message)
			assert.Equal(t, tt.input.Template, extracted.Template)
			assert.Equal(t, tt.input.Headers, extracted.Headers)
		})
	}
}
