package pathutil_test

import (
	"github.com/TykTechnologies/tyk/internal/pathutil"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestMatches(t *testing.T) {
	t.Run("errorless test cases", func(t *testing.T) {
		type positiveTestCase struct {
			name         string
			expected     bool
			samplePath   string
			existentPath string
			parameters   openapi3.Parameters
		}

		for _, tc := range []positiveTestCase{
			{"pattern matches", true, "/users/[a-z]+", "/users/{id}", openapi3.Parameters{
				newStringParameter("id", "[a-z]+"),
			}},
			{"pattern does not match", false, "/users/[a-z]+", "/users/{id}", openapi3.Parameters{
				newStringParameter("id", "[0-9]+"),
			}},
			{"pattern does not match", false, "/users/[a-z]+", "/users/{id}", openapi3.Parameters{
				newStringParameter("id", ".*"),
			}},
			{"does not match because parameter does not exist", false, "/users/[a-z]+", "/users/{id}", openapi3.Parameters{
				newStringParameter("no_id", ".*"),
			}},
			{"does not match because of mismatched type", false, "/users/[a-z]+", "/users/{id}", openapi3.Parameters{
				newParameter("id", openapi3.NewIntegerSchema().WithPattern("[a-z]+")),
			}},
			{"wider test case", false, "/users/[a-z]+", "/users/{id}/view", openapi3.Parameters{
				newParameter("id", openapi3.NewIntegerSchema().WithPattern("[a-z]+")),
			}},
			{"test case with one different", false, "/users/[a-z]+/view", "/users/{id}/view", openapi3.Parameters{
				newParameter("id", openapi3.NewIntegerSchema().WithPattern("[a-z]+")),
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ok, err := pathutil.Matches(tc.samplePath, tc.existentPath, tc.parameters)
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, ok)
			})
		}
	})
}

func TestNormalize(t *testing.T) {
	t.Run("does not return error if nil is provided", func(t *testing.T) {
		normalized, err := pathutil.Normalize(nil)
		assert.NoError(t, err)
		assert.Nil(t, normalized)
	})

	t.Run("it adds path item if no matches found", func(t *testing.T) {
		in := openapi3.NewPaths(
			openapi3.WithPath("/users/.*", &openapi3.PathItem{
				Get: &openapi3.Operation{
					Description: "get operation description",
				},
			}),
		)

		normalized, err := pathutil.Normalize(in)

		assert.NoError(t, err)
		assert.NotNil(t, normalized)
		assert.Len(t, normalized.Map(), 1)
		normalizedPathItem := normalized.Value("/users/{customRegex1}")
		pathItem := in.Value("/users/.*")

		assert.NotNil(t, normalizedPathItem)
		assert.Equal(t, normalizedPathItem.Get, pathItem.Get)
	})

	t.Run("it modifies path item all the matches", func(t *testing.T) {
		in := openapi3.NewPaths(
			openapi3.WithPath("/users/{id}", &openapi3.PathItem{
				Parameters: openapi3.Parameters{
					newStringParameter("id", "[a-z]+"),
				},
				Get: &openapi3.Operation{
					Description: "path item with id",
				},
				Post: &openapi3.Operation{Description: "id post"},
			}),

			openapi3.WithPath("/users/{name}", &openapi3.PathItem{
				Parameters: openapi3.Parameters{
					newStringParameter("name", "[a-z]+"),
				},
				Get: &openapi3.Operation{
					Description: "path item with name",
				},
				Post: &openapi3.Operation{Description: "name post"},
				Put:  &openapi3.Operation{Description: "name put"},
			}),

			openapi3.WithPath("/users/[a-z]+", &openapi3.PathItem{
				Get: &openapi3.Operation{
					Description: "get operation description with anonymous regex",
				},
			}),
		)

		normalized, err := pathutil.Normalize(in)

		assert.NoError(t, err)
		assert.NotNil(t, normalized)
		assert.Len(t, normalized.Map(), 2)

		pathItemWithId := normalized.Value("/users/{id}")
		pathItemWithName := normalized.Value("/users/{name}")

		assert.NotNil(t, pathItemWithId)
		assert.NotNil(t, pathItemWithName)

		origin := in.Value("/users/[a-z]+")
		assert.NotNil(t, origin)

		assert.Equal(t, pathItemWithId.Get, origin.Get)
		assert.Equal(t, pathItemWithName.Get, origin.Get)

		assert.Len(t, pathItemWithId.Operations(), 2)
		assert.NotNil(t, pathItemWithId.Post)

		assert.Len(t, pathItemWithName.Operations(), 3)
		assert.NotNil(t, pathItemWithName.Post)
		assert.NotNil(t, pathItemWithName.Put)
	})
}

func newStringParameter(name, pattern string) *openapi3.ParameterRef {
	return &openapi3.ParameterRef{
		Value: openapi3.
			NewPathParameter(name).
			WithSchema(openapi3.
				NewStringSchema().
				WithPattern(pattern),
			),
	}
}

func newParameter(name string, schema *openapi3.Schema) *openapi3.ParameterRef {
	return &openapi3.ParameterRef{
		Value: openapi3.
			NewPathParameter(name).
			WithSchema(schema),
	}
}
