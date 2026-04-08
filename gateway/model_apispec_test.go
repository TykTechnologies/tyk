package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestAPISpec_APIType(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *APISpec
		expected string
	}{
		{
			name: "classic API",
			setup: func() *APISpec {
				return &APISpec{APIDefinition: &apidef.APIDefinition{}}
			},
			expected: "classic",
		},
		{
			name: "OAS API",
			setup: func() *APISpec {
				spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
				spec.IsOAS = true
				return spec
			},
			expected: "oas",
		},
		{
			name: "GraphQL API",
			setup: func() *APISpec {
				spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
				spec.GraphQL.Enabled = true
				return spec
			},
			expected: "graphql",
		},
		{
			name: "MCP API",
			setup: func() *APISpec {
				spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
				spec.MarkAsMCP()
				return spec
			},
			expected: "mcp",
		},
		{
			name: "MCP takes precedence over OAS",
			setup: func() *APISpec {
				spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
				spec.MarkAsMCP()
				spec.IsOAS = true
				return spec
			},
			expected: "mcp",
		},
		{
			name: "GraphQL takes precedence over OAS",
			setup: func() *APISpec {
				spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
				spec.GraphQL.Enabled = true
				spec.IsOAS = true
				return spec
			},
			expected: "graphql",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := tt.setup()
			got := spec.APIType()
			assert.Equal(t, tt.expected, got)
		})
	}
}
