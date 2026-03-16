package apidef

import (
	"fmt"

	"github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/regexp"
)

// ErrorOverridesMap maps status codes to their override rules.
type ErrorOverridesMap map[string][]ErrorOverride

// ErrorOverride combines an optional matcher with its response.
type ErrorOverride struct {
	// Match contains optional additional matching criteria.
	Match *ErrorMatcher `json:"match,omitempty"`

	// Response defines the response to return when matched.
	Response ErrorResponse `json:"response"`

	// compiledBodyTmpl is the pre-compiled text/template for inline Body.
	compiledBodyTmpl any `json:"-" ignored:"true"`

	// compiledBodyTmplHTML is the pre-compiled html/template for inline Body.
	compiledBodyTmplHTML any `json:"-" ignored:"true"`
}

// SetCompiledTemplates stores the pre-compiled templates for inline Body.
func (e *ErrorOverride) SetCompiledTemplates(textTmpl, htmlTmpl any) {
	e.compiledBodyTmpl = textTmpl
	e.compiledBodyTmplHTML = htmlTmpl
}

// GetCompiledTemplate returns the pre-compiled template for the given content type.
// Returns nil if no inline Body template was compiled (e.g., using file template).
func (e *ErrorOverride) GetCompiledTemplate(isXML bool) any {
	if isXML {
		return e.compiledBodyTmpl
	}

	return e.compiledBodyTmplHTML
}

// HasCompiledTemplate returns true if this override has a pre-compiled inline Body template.
func (e *ErrorOverride) HasCompiledTemplate() bool {
	return e.compiledBodyTmpl != nil
}

// ErrorMatcher defines additional matching criteria for error overrides.
type ErrorMatcher struct {
	// Flag matches against the error classification flag from the request context.
	Flag errors.ResponseFlag `json:"flag,omitempty"`

	// MessagePattern is a regex pattern to match against the response body.
	MessagePattern string `json:"message_pattern,omitempty"`

	// BodyField is a JSON path (gjson syntax) to extract a value from the response body.
	BodyField string `json:"body_field,omitempty"`

	// BodyValue is the expected value at BodyField for the match to succeed.
	BodyValue string `json:"body_value,omitempty"`

	// CompiledPattern is the pre-compiled regex for MessagePattern.
	CompiledPattern *regexp.Regexp `json:"-" ignored:"true"`
}

// Compile compiles the MessagePattern regex if present.
// Should be called after unmarshaling from JSON or YAML.
func (m *ErrorMatcher) Compile() error {
	if m.MessagePattern != "" && m.CompiledPattern == nil {
		re, err := regexp.Compile(m.MessagePattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern %q: %w", m.MessagePattern, err)
		}

		m.CompiledPattern = re
	}

	return nil
}

// ErrorResponse defines the override response for error overrides.
type ErrorResponse struct {
	// Code is the HTTP status code to return.
	Code int `json:"code"`

	// Body is the HTTP response body (literal or inline template).
	Body string `json:"body,omitempty"`

	// Message is the semantic error message passed to templates as {{.Message}}.
	Message string `json:"message,omitempty"`

	// Template references an error template file in the templates/ directory.
	Template string `json:"template,omitempty"`

	// Headers are HTTP headers to include in the response.
	Headers map[string]string `json:"headers,omitempty"`
}
