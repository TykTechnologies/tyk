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
	Match *ErrorMatcher `bson:"match,omitempty" json:"match,omitempty"`

	// Response defines the response to return when matched.
	Response ErrorResponse `bson:"response" json:"response"`

	// compiledBodyTmpl is the pre-compiled text/template for inline Body.
	compiledBodyTmpl any `bson:"-" json:"-" ignored:"true"`

	// compiledBodyTmplHTML is the pre-compiled html/template for inline Body.
	compiledBodyTmplHTML any `bson:"-" json:"-" ignored:"true"`
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
	Flag errors.ResponseFlag `bson:"flag,omitempty" json:"flag,omitempty"`

	// MessagePattern is a regex pattern to match against the response body.
	MessagePattern string `bson:"message_pattern,omitempty" json:"message_pattern,omitempty"`

	// BodyField is a JSON path (gjson syntax) to extract a value from the response body.
	BodyField string `bson:"body_field,omitempty" json:"body_field,omitempty"`

	// BodyValue is the expected value at BodyField for the match to succeed.
	BodyValue string `bson:"body_value,omitempty" json:"body_value,omitempty"`

	// CompiledPattern is the pre-compiled regex for MessagePattern.
	CompiledPattern *regexp.Regexp `bson:"-" json:"-" ignored:"true"`
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
	// StatusCode is the HTTP status code to return.
	StatusCode int `bson:"status_code" json:"status_code"`

	// Body is the HTTP response body (literal or inline template).
	Body string `bson:"body,omitempty" json:"body,omitempty"`

	// Message is the semantic error message passed to templates as {{.Message}}.
	Message string `bson:"message,omitempty" json:"message,omitempty"`

	// Template references an error template file in the templates/ directory.
	Template string `bson:"template,omitempty" json:"template,omitempty"`

	// Headers are HTTP headers to include in the response.
	Headers map[string]string `bson:"headers,omitempty" json:"headers,omitempty"`
}
