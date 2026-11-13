package pathnormalizer

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

// TestDenormalize covers turning a normalized path back into the user-defined
// path it was generated from.
func TestDenormalize(t *testing.T) {
	t.Parallel()

	pathParam := func(name, pattern string) *openapi3.ParameterRef {
		schema := openapi3.NewStringSchema()
		if pattern != "" {
			schema = schema.WithPattern(pattern)
		}

		return &openapi3.ParameterRef{Value: &openapi3.Parameter{
			Name: name, In: openapi3.ParameterInPath, Required: true,
			Schema: &openapi3.SchemaRef{Value: schema},
		}}
	}

	tests := map[string]struct {
		path   string
		params openapi3.Parameters
		want   string
	}{
		"generated placeholder is restored": {
			path:   "/users/{customRegex1}",
			params: openapi3.Parameters{pathParam("customRegex1", "[a-z]+")},
			want:   "/users/[a-z]+",
		},
		"every generated placeholder on the path is restored": {
			path: "/user/{customRegex1}/account/{customRegex2}",
			params: openapi3.Parameters{
				pathParam("customRegex1", "[a-zA-Z]+"),
				pathParam("customRegex2", "[0-9]+"),
			},
			want: "/user/[a-zA-Z]+/account/[0-9]+",
		},
		// A name the user chose is theirs, and so is the path shape they wrote.
		"user named parameter is left alone": {
			path:   "/users/{userId}",
			params: openapi3.Parameters{pathParam("userId", "[0-9]+")},
			want:   "/users/{userId}",
		},
		"placeholder without a pattern is left alone": {
			path:   "/users/{customRegex1}",
			params: openapi3.Parameters{pathParam("customRegex1", "")},
			want:   "/users/{customRegex1}",
		},
		"a name that only looks generated is left alone": {
			path:   "/users/{customRegexFoo}",
			params: openapi3.Parameters{pathParam("customRegexFoo", "[a-z]+")},
			want:   "/users/{customRegexFoo}",
		},
		"path without placeholders is left alone": {
			path:   "/users/list",
			params: nil,
			want:   "/users/list",
		},
		"a query parameter never rewrites the path": {
			path: "/users/{customRegex1}",
			params: openapi3.Parameters{{Value: &openapi3.Parameter{
				Name: "customRegex1", In: openapi3.ParameterInQuery,
				Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithPattern("[a-z]+")},
			}}},
			want: "/users/{customRegex1}",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, Denormalize(tc.path, tc.params))
		})
	}
}
