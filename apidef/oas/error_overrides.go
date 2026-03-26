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

type ErrorOverrides struct {
	Enabled bool              `json:"enabled"`
	Value   ErrorOverridesMap `json:"value"`
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

type ErrorOverride struct {
	Match    *ErrorMatcher `json:"match,omitempty"`
	Response ErrorResponse `json:"response"`
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

type ErrorMatcher struct {
	Flag           errors.ResponseFlag `json:"flag,omitempty"`
	MessagePattern string              `json:"messagePattern,omitempty"`
	BodyField      string              `json:"bodyField,omitempty"`
	BodyValue      string              `json:"bodyValue,omitempty"`
}

func (em *ErrorMatcher) ExtractTo(api *apidef.ErrorMatcher) {
	api.Flag = em.Flag
	api.MessagePattern = em.MessagePattern
	api.BodyField = em.BodyField
	api.BodyValue = em.BodyValue

}

type ErrorResponse struct {
	StatusCode int               `json:"statusCode"`
	Body       string            `json:"body,omitempty"`
	Message    string            `json:"message,omitempty"`
	Template   string            `json:"template,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

func (er ErrorResponse) ExtractTo(api *apidef.ErrorResponse) {
	api.StatusCode = er.StatusCode
	api.Body = er.Body
	api.Message = er.Message
	api.Template = er.Template
	api.Headers = er.Headers
}
