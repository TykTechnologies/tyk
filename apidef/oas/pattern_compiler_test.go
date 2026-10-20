package oas

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pydanticDecimalLookahead is the pattern Pydantic v2 emits for a nullable
// Decimal field: valid ECMA-262, uncompilable by RE2 (issue #8321).
const pydanticDecimalLookahead = "^(?!^[-+.]*$)[+-]?0*\\d*\\.?\\d*$"

func lookaheadDecimalSchema() *openapi3.Schema {
	return &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"value": &openapi3.SchemaRef{
				Value: &openapi3.Schema{
					AnyOf: []*openapi3.SchemaRef{
						{
							Value: &openapi3.Schema{
								Type:    &openapi3.Types{"string"},
								Pattern: pydanticDecimalLookahead,
							},
						},
						{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{"null"},
							},
						},
					},
				},
			},
		},
	}
}

func TestOAS_Validate_LookaheadPatternOAS31(t *testing.T) {
	t.Parallel()

	oas := createBaseOAS("3.1.2", "lookahead-pattern")
	oas.Components = &openapi3.Components{
		Schemas: openapi3.Schemas{
			"Package": &openapi3.SchemaRef{Value: lookaheadDecimalSchema()},
		},
	}
	addPostOperationWithRequestBodySchema(oas, "/package", lookaheadDecimalSchema())
	addMinimalTykExtension(oas)

	require.NoError(t, oas.Validate(context.Background()))
}

func TestOAS_Validate_LookaheadPatternOAS30(t *testing.T) {
	t.Parallel()

	oas := createBaseOAS("3.0.3", "lookahead-pattern")
	addPostOperationWithRequestBodySchema(oas, "/package", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"value": &openapi3.SchemaRef{
				Value: &openapi3.Schema{
					Type:    &openapi3.Types{"string"},
					Pattern: pydanticDecimalLookahead,
				},
			},
		},
	})
	addMinimalTykExtension(oas)

	require.NoError(t, oas.Validate(context.Background()))
}

func TestOAS_Validate_StillRejectsUnsupportedTypes(t *testing.T) {
	t.Parallel()

	oas := createBaseOAS("3.0.3", "null-type-3.0")
	addPostOperationWithRequestBodySchema(oas, "/package", &openapi3.Schema{
		Type: &openapi3.Types{"null"},
	})
	addMinimalTykExtension(oas)

	err := oas.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported 'type' value")
}

func TestForgivingPatternCompiler(t *testing.T) {
	t.Parallel()

	t.Run("uncompilable pattern matches everything", func(t *testing.T) {
		m, err := ForgivingPatternCompiler(pydanticDecimalLookahead)
		require.NoError(t, err)
		assert.True(t, m.MatchString("12.50"))
		assert.True(t, m.MatchString("anything at all"))
	})

	t.Run("compilable pattern is enforced", func(t *testing.T) {
		m, err := ForgivingPatternCompiler("^[a-z]+-[0-9]+$")
		require.NoError(t, err)
		assert.True(t, m.MatchString("abc-123"))
		assert.False(t, m.MatchString("123-abc"))
	})

	t.Run("unicode escapes are translated like kin-openapi does", func(t *testing.T) {
		m, err := ForgivingPatternCompiler(`^\u0041$`)
		require.NoError(t, err)
		assert.True(t, m.MatchString("A"))
		assert.False(t, m.MatchString("B"))
	})
}
