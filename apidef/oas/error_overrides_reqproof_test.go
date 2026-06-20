package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/errors"
)

// Verifies: SYS-REQ-104, SW-REQ-051
// SW-REQ-051:nominal:nominal
// SW-REQ-051:boundary:nominal
// SW-REQ-051:error_handling:nominal
// SW-REQ-051:error_handling:negative
// SW-REQ-051:determinism:nominal
func TestErrorOverridesPreserveOASExtensionShape(t *testing.T) {
	t.Run("top level enabled flag and override map round trip", func(t *testing.T) {
		source := apidef.APIDefinition{
			ErrorOverridesDisabled: false,
			ErrorOverrides: apidef.ErrorOverridesMap{
				"404": {
					{
						Match: &apidef.ErrorMatcher{
							Flag:           errors.TLE,
							MessagePattern: "timeout.*",
							BodyField:      "error.code",
							BodyValue:      "TIMEOUT",
						},
						Response: apidef.ErrorResponse{
							StatusCode: 504,
							Body:       `{"error":"upstream unavailable"}`,
							Message:    "Gateway Timeout",
							Template:   "timeout.html",
							Headers:    map[string]string{"X-Tyk-Override": "timeout"},
						},
					},
					{
						Response: apidef.ErrorResponse{
							StatusCode: 404,
							Body:       `{"error":"not found"}`,
						},
					},
				},
				"500": {
					{
						Response: apidef.ErrorResponse{
							StatusCode: 500,
							Template:   "error_500.tmpl",
						},
					},
				},
			},
		}

		var first ErrorOverrides
		first.Fill(source)
		var second ErrorOverrides
		second.Fill(source)

		assert.True(t, first.Enabled)
		assert.Equal(t, first, second)
		assert.Len(t, first.Value, 2)
		assert.Equal(t, errors.TLE, first.Value["404"][0].Match.Flag)
		assert.Equal(t, "timeout.*", first.Value["404"][0].Match.MessagePattern)
		assert.Equal(t, "error.code", first.Value["404"][0].Match.BodyField)
		assert.Equal(t, "TIMEOUT", first.Value["404"][0].Match.BodyValue)
		assert.Equal(t, 504, first.Value["404"][0].Response.StatusCode)
		assert.Equal(t, "Gateway Timeout", first.Value["404"][0].Response.Message)
		assert.Equal(t, "timeout.html", first.Value["404"][0].Response.Template)
		assert.Equal(t, "timeout", first.Value["404"][0].Response.Headers["X-Tyk-Override"])
		assert.Nil(t, first.Value["404"][1].Match)

		var extracted apidef.APIDefinition
		first.ExtractTo(&extracted)
		assert.False(t, extracted.ErrorOverridesDisabled)
		assert.Equal(t, source.ErrorOverrides, extracted.ErrorOverrides)
	})

	t.Run("disabled and empty overrides preserve explicit disabled state", func(t *testing.T) {
		var oasOverrides ErrorOverrides
		oasOverrides.Fill(apidef.APIDefinition{
			ErrorOverridesDisabled: true,
			ErrorOverrides:         nil,
		})

		assert.False(t, oasOverrides.Enabled)
		assert.Nil(t, oasOverrides.Value)

		oasOverrides = ErrorOverrides{Enabled: false, Value: ErrorOverridesMap{}}
		var extracted apidef.APIDefinition
		oasOverrides.ExtractTo(&extracted)
		assert.True(t, extracted.ErrorOverridesDisabled)
		assert.Nil(t, extracted.ErrorOverrides)
	})

	t.Run("nil and empty maps do not allocate classic overrides", func(t *testing.T) {
		var empty ErrorOverridesMap
		empty.Fill(apidef.APIDefinition{})
		assert.Nil(t, empty)

		var nilReceiver *ErrorOverridesMap
		api := &apidef.APIDefinition{}
		nilReceiver.ExtractTo(api)
		assert.Nil(t, api.ErrorOverrides)

		empty = ErrorOverridesMap{}
		empty.ExtractTo(api)
		assert.Nil(t, api.ErrorOverrides)
	})

	t.Run("matcher and response helpers preserve optional fields", func(t *testing.T) {
		override := ErrorOverride{
			Match: &ErrorMatcher{
				Flag:           "upstream_timeout",
				MessagePattern: "timeout.*",
				BodyField:      "error.code",
				BodyValue:      "TIMEOUT",
			},
			Response: ErrorResponse{
				StatusCode: 502,
				Body:       `{"error":"bad gateway"}`,
				Message:    "Bad Gateway",
				Template:   "bad_gateway.html",
				Headers:    map[string]string{"Retry-After": "30"},
			},
		}

		var extracted apidef.ErrorOverride
		override.ExtractTo(&extracted)

		assert.Equal(t, apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				Flag:           "upstream_timeout",
				MessagePattern: "timeout.*",
				BodyField:      "error.code",
				BodyValue:      "TIMEOUT",
			},
			Response: apidef.ErrorResponse{
				StatusCode: 502,
				Body:       `{"error":"bad gateway"}`,
				Message:    "Bad Gateway",
				Template:   "bad_gateway.html",
				Headers:    map[string]string{"Retry-After": "30"},
			},
		}, extracted)
	})
}
