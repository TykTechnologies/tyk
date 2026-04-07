package httputil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

func TestSchemaTypeToRegex(t *testing.T) {
	tests := []struct {
		name       string
		schemaType string
		want       string
	}{
		{"string type", "string", `[^/]+`},
		{"number type", "number", `[0-9]*\.?[0-9]+`},
		{"integer type", "integer", `[0-9]+`},
		{"boolean type", "boolean", `true|false`},
		{"empty type", "", `[^/]+`},
		{"unknown type", "object", `[^/]+`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, httputil.SchemaTypeToRegex(tc.schemaType))
		})
	}
}

func TestParamSchemaToRegex(t *testing.T) {
	tests := []struct {
		name string
		ps   httputil.ParamSchema
		want string
	}{
		{
			name: "explicit pattern used over type",
			ps:   httputil.ParamSchema{Pattern: "[a-z]", Type: "string"},
			want: "[a-z]",
		},
		{
			name: "pattern with anchors stripped",
			ps:   httputil.ParamSchema{Pattern: "^[a-z]$"},
			want: "[a-z]",
		},
		{
			name: "type fallback when no pattern",
			ps:   httputil.ParamSchema{Type: "integer"},
			want: `[0-9]+`,
		},
		{
			name: "no pattern no type",
			ps:   httputil.ParamSchema{},
			want: `[^/]+`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, httputil.ParamSchemaToRegex(tc.ps))
		})
	}
}

func TestPrepareSubSpecRegexp(t *testing.T) {
	tests := []struct {
		name         string
		pattern      string
		paramSchemas map[string]httputil.ParamSchema
		prefix       bool
		suffix       bool
		want         string
	}{
		{
			name:    "single string param with pattern",
			pattern: "/employees/{prct}",
			paramSchemas: map[string]httputil.ParamSchema{
				"prct": {Pattern: "^[a-z]$", Type: "string"},
			},
			prefix: true,
			suffix: true,
			want:   `^/employees/([a-z])$`,
		},
		{
			name:    "single number param with pattern",
			pattern: "/employees/{zd}",
			paramSchemas: map[string]httputil.ParamSchema{
				"zd": {Pattern: "[1-9]", Type: "number"},
			},
			prefix: true,
			suffix: true,
			want:   `^/employees/([1-9])$`,
		},
		{
			name:    "type-based fallback for integer",
			pattern: "/users/{id}",
			paramSchemas: map[string]httputil.ParamSchema{
				"id": {Type: "integer"},
			},
			prefix: true,
			suffix: true,
			want:   `^/users/([0-9]+)$`,
		},
		{
			name:    "multiple params in one path",
			pattern: "/dept/{deptId}/employees/{empId}",
			paramSchemas: map[string]httputil.ParamSchema{
				"deptId": {Type: "integer"},
				"empId":  {Pattern: "^[a-z]+$", Type: "string"},
			},
			prefix: true,
			suffix: true,
			want:   `^/dept/([0-9]+)/employees/([a-z]+)$`,
		},
		{
			name:    "param not in schema falls back to generic",
			pattern: "/items/{id}/{sub}",
			paramSchemas: map[string]httputil.ParamSchema{
				"id": {Type: "integer"},
			},
			prefix: true,
			suffix: true,
			want:   `^/items/([0-9]+)/([^/]+)$`,
		},
		{
			name:    "no prefix no suffix",
			pattern: "/users/{id}",
			paramSchemas: map[string]httputil.ParamSchema{
				"id": {Type: "string"},
			},
			prefix: false,
			suffix: false,
			want:   `/users/([^/]+)`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := httputil.PrepareSubSpecRegexp(tc.pattern, tc.paramSchemas, tc.prefix, tc.suffix)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCompileSubSpec(t *testing.T) {
	t.Run("returns nil for static path", func(t *testing.T) {
		result := httputil.CompileSubSpec("/employees/static", nil, true, true)
		assert.Nil(t, result)
	})

	t.Run("returns nil for empty param schemas", func(t *testing.T) {
		result := httputil.CompileSubSpec("/employees/{id}", map[string]httputil.ParamSchema{}, true, true)
		assert.Nil(t, result)
	})

	t.Run("compiles valid sub-spec", func(t *testing.T) {
		result := httputil.CompileSubSpec("/employees/{id}", map[string]httputil.ParamSchema{
			"id": {Pattern: "[a-z]+"},
		}, true, true)
		assert.NotNil(t, result)
		assert.True(t, result.MatchString("/employees/abc"))
		assert.False(t, result.MatchString("/employees/123"))
	})

	t.Run("returns nil for invalid regex pattern", func(t *testing.T) {
		result := httputil.CompileSubSpec("/employees/{id}", map[string]httputil.ParamSchema{
			"id": {Pattern: "[invalid"},
		}, true, true)
		assert.Nil(t, result)
	})
}
