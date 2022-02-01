package jsonschema

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"unicode/utf8"

	jptr "github.com/qri-io/jsonpointer"
)

// MaxLength defines the maxLenght JSON Schema keyword
type MaxLength int

// NewMaxLength allocates a new MaxLength keyword
func NewMaxLength() Keyword {
	return new(MaxLength)
}

// Register implements the Keyword interface for MaxLength
func (m *MaxLength) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for MaxLength
func (m *MaxLength) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for MaxLength
func (m MaxLength) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[MaxLength] Validating")
	if str, ok := data.(string); ok {
		if utf8.RuneCountInString(str) > int(m) {
			currentState.AddError(data, fmt.Sprintf("max length of %d characters exceeded: %s", m, str))
		}
	}
}

// MinLength defines the maxLenght JSON Schema keyword
type MinLength int

// NewMinLength allocates a new MinLength keyword
func NewMinLength() Keyword {
	return new(MinLength)
}

// Register implements the Keyword interface for MinLength
func (m *MinLength) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for MinLength
func (m *MinLength) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for MinLength
func (m MinLength) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[MinLength] Validating")
	if str, ok := data.(string); ok {
		if utf8.RuneCountInString(str) < int(m) {
			currentState.AddError(data, fmt.Sprintf("min length of %d characters required: %s", m, str))
		}
	}
}

// Pattern defines the pattern JSON Schema keyword
type Pattern regexp.Regexp

// NewPattern allocates a new Pattern keyword
func NewPattern() Keyword {
	return &Pattern{}
}

// Register implements the Keyword interface for Pattern
func (p *Pattern) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Pattern
func (p *Pattern) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for Pattern
func (p Pattern) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Pattern] Validating")
	re := regexp.Regexp(p)
	if str, ok := data.(string); ok {
		if !re.Match([]byte(str)) {
			currentState.AddError(data, fmt.Sprintf("regexp pattern %s mismatch on string: %s", re.String(), str))
		}
	}
}

// UnmarshalJSON implements the json.Unmarshaler interface for Pattern
func (p *Pattern) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	ptn, err := regexp.Compile(str)
	if err != nil {
		return err
	}

	*p = Pattern(*ptn)
	return nil
}

// MarshalJSON implements the json.Marshaler interface for Pattern
func (p Pattern) MarshalJSON() ([]byte, error) {
	re := regexp.Regexp(p)
	rep := &re
	return json.Marshal(rep.String())
}
