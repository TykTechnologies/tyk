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

type ErrorOverridesMap map[string][]ErrorOverride

func (e *ErrorOverridesMap) Fill(internal apidef.APIDefinition) {
	if len(internal.ErrorOverrides) == 0 {
		return
	}

	if *e == nil {
		*e = make(ErrorOverridesMap)
	}

	for code, overrides := range internal.ErrorOverrides {
		oasOverrides := make([]ErrorOverride, len(overrides))

		for i, apiOverride := range overrides {
			oasOverrides[i].Fill(apiOverride)
		}

		(*e)[code] = oasOverrides
	}
}

func (e *ErrorOverridesMap) ExtractTo(internal *apidef.APIDefinition) {
	if e == nil || len(*e) == 0 {
		return
	}

	if internal.ErrorOverrides == nil {
		internal.ErrorOverrides = make(apidef.ErrorOverridesMap)
	}

	for code, oasOverrides := range *e {
		internalOverride := make([]apidef.ErrorOverride, len(oasOverrides))

		for i, oasOverride := range oasOverrides {
			oasOverride.ExtractTo(&internalOverride[i])
		}

		internal.ErrorOverrides[code] = internalOverride
	}
}

// ErrorOverride matches apidef.ErrorOverride but with camelCase tags for OAS.
type ErrorOverride struct {
	Match    *ErrorMatcher `json:"match,omitempty"`
	Response ErrorResponse `json:"response"`
}

func (eo *ErrorOverride) Fill(internal apidef.ErrorOverride) {
	if internal.Match != nil {
		eo.Match = &ErrorMatcher{
			Flag:           internal.Match.Flag,
			MessagePattern: internal.Match.MessagePattern,
			BodyField:      internal.Match.BodyField,
			BodyValue:      internal.Match.BodyValue,
		}
	}
	eo.Response = ErrorResponse{
		StatusCode: internal.Response.StatusCode,
		Body:       internal.Response.Body,
		Message:    internal.Response.Message,
		Template:   internal.Response.Template,
		Headers:    internal.Response.Headers,
	}
}

func (eo *ErrorOverride) ExtractTo(internal *apidef.ErrorOverride) {
	if eo.Match != nil {
		internal.Match = &apidef.ErrorMatcher{}
		eo.Match.ExtractTo(internal.Match)
	}

	eo.Response.ExtractTo(&internal.Response)
}

type ErrorMatcher struct {
	Flag           errors.ResponseFlag `json:"flag,omitempty"`
	MessagePattern string              `json:"messagePattern,omitempty"`
	BodyField      string              `json:"bodyField,omitempty"`
	BodyValue      string              `json:"bodyValue,omitempty"`
}

func (em *ErrorMatcher) ExtractTo(internal *apidef.ErrorMatcher) {
	internal.Flag = em.Flag
	internal.MessagePattern = em.MessagePattern
	internal.BodyField = em.BodyField
	internal.BodyValue = em.BodyValue

}

type ErrorResponse struct {
	StatusCode int               `json:"statusCode"`
	Body       string            `json:"body,omitempty"`
	Message    string            `json:"message,omitempty"`
	Template   string            `json:"template,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

func (er ErrorResponse) ExtractTo(internal *apidef.ErrorResponse) {
	internal.StatusCode = er.StatusCode
	internal.Body = er.Body
	internal.Message = er.Message
	internal.Template = er.Template
	internal.Headers = er.Headers
}
