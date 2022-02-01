package jsonschema

import (
	"context"
	"fmt"

	jptr "github.com/qri-io/jsonpointer"
)

// MultipleOf defines the multipleOf JSON Schema keyword
type MultipleOf float64

// NewMultipleOf allocates a new MultipleOf keyword
func NewMultipleOf() Keyword {
	return new(MultipleOf)
}

// Register implements the Keyword interface for MultipleOf
func (m *MultipleOf) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for MultipleOf
func (m *MultipleOf) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for MultipleOf
func (m MultipleOf) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[MultipleOf] Validating")
	if num, ok := convertNumberToFloat(data); ok {
		div := num / float64(m)
		if float64(int(div)) != div {
			currentState.AddError(data, fmt.Sprintf("must be a multiple of %v", m))
		}
	}
}

// Maximum defines the maximum JSON Schema keyword
type Maximum float64

// NewMaximum allocates a new Maximum keyword
func NewMaximum() Keyword {
	return new(Maximum)
}

// Register implements the Keyword interface for Maximum
func (m *Maximum) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Maximum
func (m *Maximum) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for Maximum
func (m Maximum) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Maximum] Validating")
	if num, ok := convertNumberToFloat(data); ok {
		if num > float64(m) {
			currentState.AddError(data, fmt.Sprintf("must be less than or equal to %v", m))
		}
	}
}

// ExclusiveMaximum defines the exclusiveMaximum JSON Schema keyword
type ExclusiveMaximum float64

// NewExclusiveMaximum allocates a new ExclusiveMaximum keyword
func NewExclusiveMaximum() Keyword {
	return new(ExclusiveMaximum)
}

// Register implements the Keyword interface for ExclusiveMaximum
func (m *ExclusiveMaximum) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for ExclusiveMaximum
func (m *ExclusiveMaximum) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for ExclusiveMaximum
func (m ExclusiveMaximum) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[ExclusiveMaximum] Validating")
	if num, ok := convertNumberToFloat(data); ok {
		if num >= float64(m) {
			currentState.AddError(data, fmt.Sprintf("%v must be less than %v", num, m))
		}
	}
}

// Minimum defines the minimum JSON Schema keyword
type Minimum float64

// NewMinimum allocates a new Minimum keyword
func NewMinimum() Keyword {
	return new(Minimum)
}

// Register implements the Keyword interface for Minimum
func (m *Minimum) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Minimum
func (m *Minimum) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for Minimum
func (m Minimum) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Minimum] Validating")
	if num, ok := convertNumberToFloat(data); ok {
		if num < float64(m) {
			currentState.AddError(data, fmt.Sprintf("must be greater than or equal to %v", m))
		}
	}
}

// ExclusiveMinimum defines the exclusiveMinimum JSON Schema keyword
type ExclusiveMinimum float64

// NewExclusiveMinimum allocates a new ExclusiveMinimum keyword
func NewExclusiveMinimum() Keyword {
	return new(ExclusiveMinimum)
}

// Register implements the Keyword interface for ExclusiveMinimum
func (m *ExclusiveMinimum) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for ExclusiveMinimum
func (m *ExclusiveMinimum) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for ExclusiveMinimum
func (m ExclusiveMinimum) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[ExclusiveMinimum] Validating")
	if num, ok := convertNumberToFloat(data); ok {
		if num <= float64(m) {
			currentState.AddError(data, fmt.Sprintf("%v must be greater than %v", num, m))
		}
	}
}

func convertNumberToFloat(data interface{}) (float64, bool) {
	switch v := data.(type) {
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return float64(v), true
	case uintptr:
		return float64(v), true
	}

	return 0, false
}
