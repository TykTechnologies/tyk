package gojsonschema

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Verifies: STK-REQ-019, SYS-REQ-107, SW-REQ-039
// STK-REQ-019:nominal:nominal
// STK-REQ-019:error_handling:negative
// SYS-REQ-107:nominal:nominal
// SYS-REQ-107:error_handling:negative
// SW-REQ-039:nominal:nominal
// SW-REQ-039:error_handling:negative
func TestGoJSONSchemaFacadeRequirement(t *testing.T) {
	schema := map[string]any{
		"type":     "object",
		"required": []string{"name"},
		"properties": map[string]any{
			"name": map[string]any{"type": "string"},
		},
	}

	var schemaLoader JSONLoader = NewGoLoader(schema)

	validResult, err := Validate(schemaLoader, NewGoLoader(map[string]any{"name": "mcp"}))
	require.NoError(t, err)
	require.True(t, validResult.Valid())

	invalidResult, err := Validate(schemaLoader, NewBytesLoader([]byte(`{"name": 10}`)))
	require.NoError(t, err)
	require.False(t, invalidResult.Valid())
	require.NotEmpty(t, invalidResult.Errors())

	var firstError ResultError = invalidResult.Errors()[0]
	require.NotEmpty(t, firstError.String())
	require.NotNil(t, FormatCheckers)
}
