package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/errors"
)

// The types in this file intentionally mirror types in the 'apidef' package but use camelCase JSON tags.
//
// This duplication is necessary because:
// 1. The 'x-tyk-api-gateway' OAS extension follows a camelCase convention to align with
// standard OpenAPI practices.
// 2. The internal 'apidef' structures use snake_case to maintain compatibility with Tyk's
// Classic API definitions and 'tyk.conf'.

// ErrorOverrides defines the OAS extension configuration for error overrides.
type ErrorOverrides struct {
	// Enabled determines if error overrides are active for this API.
	// Maps to Tyk classic API definition: `error_overrides_disabled`
	Enabled bool `bson:"enabled" json:"enabled"`

	// Value contains the map of status codes to their override rules.
	Value ErrorOverridesMap `bson:"value,omitempty" json:"value,omitempty"`
}

func (e *ErrorOverrides) Fill(api apidef.APIDefinition) {
	e.Enabled = !api.ErrorOverridesDisabled

	if len(api.ErrorOverrides) > 0 {
		e.Value = make(ErrorOverridesMap)
		e.Value.Fill(api)
	}
}

func (e *ErrorOverrides) ExtractTo(api *apidef.APIDefinition) {
	api.ErrorOverridesDisabled = !e.Enabled

	if len(e.Value) == 0 {
		api.ErrorOverrides = nil

		return
	}

	api.ErrorOverrides = make(apidef.ErrorOverridesMap)
	e.Value.ExtractTo(api)
}

// ErrorOverridesMap maps status codes to their override rules.
type ErrorOverridesMap map[string][]ErrorOverride

func (e *ErrorOverridesMap) Fill(api apidef.APIDefinition) {
	if len(api.ErrorOverrides) == 0 {
		return
	}

	if *e == nil {
		*e = make(ErrorOverridesMap)
	}

	for code, overrides := range api.ErrorOverrides {
		oasOverrides := make([]ErrorOverride, len(overrides))

		for i, apiOverride := range overrides {
			oasOverrides[i].Fill(apiOverride)
		}

		(*e)[code] = oasOverrides
	}
}

func (e *ErrorOverridesMap) ExtractTo(api *apidef.APIDefinition) {
	if e == nil || len(*e) == 0 {
		return
	}

	if api.ErrorOverrides == nil {
		api.ErrorOverrides = make(apidef.ErrorOverridesMap)
	}

	for code, oasOverrides := range *e {
		apiOverride := make([]apidef.ErrorOverride, len(oasOverrides))

		for i, oasOverride := range oasOverrides {
			oasOverride.ExtractTo(&apiOverride[i])
		}

		api.ErrorOverrides[code] = apiOverride
	}
}

// ErrorOverride combines an optional matcher with its response.
type ErrorOverride struct {
	// Match contains optional additional matching criteria.
	Match *ErrorMatcher `bson:"match,omitempty" json:"match,omitempty"`

	// Response defines the response to return when matched.
	Response ErrorResponse `bson:"response" json:"response"`
}

func (eo *ErrorOverride) Fill(api apidef.ErrorOverride) {
	if api.Match != nil {
		eo.Match = &ErrorMatcher{
			Flag:           api.Match.Flag,
			MessagePattern: api.Match.MessagePattern,
			BodyField:      api.Match.BodyField,
			BodyValue:      api.Match.BodyValue,
		}
	}
	eo.Response = ErrorResponse{
		StatusCode: api.Response.StatusCode,
		Body:       api.Response.Body,
		Message:    api.Response.Message,
		Template:   api.Response.Template,
		Headers:    api.Response.Headers,
	}
}

func (eo *ErrorOverride) ExtractTo(api *apidef.ErrorOverride) {
	if eo.Match != nil {
		api.Match = &apidef.ErrorMatcher{}
		eo.Match.ExtractTo(api.Match)
	}

	eo.Response.ExtractTo(&api.Response)
}

// ErrorMatcher defines additional matching criteria for error overrides.
type ErrorMatcher struct {
	// Flag matches against the error classification flag from the request context.
	Flag errors.ResponseFlag `bson:"flag,omitempty" json:"flag,omitempty"`

	// MessagePattern is a regex pattern to match against the response body.
	MessagePattern string `bson:"messagePattern,omitempty" json:"messagePattern,omitempty"`

	// BodyField is a JSON path (gjson syntax) to extract a value from the response body.
	BodyField string `bson:"bodyField,omitempty" json:"bodyField,omitempty"`

	// BodyValue is the expected value at BodyField for the match to succeed.
	BodyValue string `bson:"bodyValue,omitempty" json:"bodyValue,omitempty"`
}

func (em *ErrorMatcher) ExtractTo(api *apidef.ErrorMatcher) {
	api.Flag = em.Flag
	api.MessagePattern = em.MessagePattern
	api.BodyField = em.BodyField
	api.BodyValue = em.BodyValue
}

// ErrorResponse defines the override response for error overrides.
type ErrorResponse struct {
	// StatusCode is the HTTP status code to return.
	StatusCode int `bson:"statusCode" json:"statusCode"`

	// Body is the HTTP response body (literal or inline template).
	Body string `bson:"body,omitempty" json:"body,omitempty"`

	// Message is the semantic error message passed to templates as {{.Message}}.
	Message string `bson:"message,omitempty" json:"message,omitempty"`

	// Template references an error template file in the templates/ directory.
	Template string `bson:"template,omitempty" json:"template,omitempty"`

	// Headers are HTTP headers to include in the response.
	Headers map[string]string `bson:"headers,omitempty" json:"headers,omitempty"`
}

func (er ErrorResponse) ExtractTo(api *apidef.ErrorResponse) {
	api.StatusCode = er.StatusCode
	api.Body = er.Body
	api.Message = er.Message
	api.Template = er.Template
	api.Headers = er.Headers
}
