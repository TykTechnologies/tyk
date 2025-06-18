package pathnormalizer_test

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/pathnormalizer"
)

func TestParser(t *testing.T) {
	t.Parallel()

	t.Run("ParsePath positive cases", func(t *testing.T) {
		type testCase struct {
			name             string
			path             string
			expectedIdPrefix string
			expectedParams   map[string]string
		}

		parser := pathnormalizer.NewParser()
		emptyMap := make(map[string]string)

		for _, tc := range []testCase{

			{"parses some data", "/hello/world", "hello/world", emptyMap},
			{"removes duplicated slashes", "/hello//world", "hello/world", emptyMap},
			{"leaves trailing slash", "/hello//world//", "hello/world/", emptyMap},
			{"parses anonymous regexp", "/users/[0-9]+", fmt.Sprintf("users/%s", anonRePattern(1)), map[string]string{
				anonRe(1): "[0-9]+",
			}},
			{"parses anonymous regexp wis trailing slash", "/users/[0-9]+/", fmt.Sprintf("users/%s/", anonRePattern(2)), map[string]string{
				anonRe(2): "[0-9]+",
			}},
			{"parses mux patterns", "/users/{id:[0-9]+/}", "users/{id}", map[string]string{
				"id": "[0-9]+",
			}},

			// Edson's test-cases
			{"empty path", "", "", emptyMap},
			{"path with regex", "/test/.*/end", "test/.*/end", map[string]string{
				anonRe(3): ".*/end",
			}},
			{"path with curly braces", "/users/{id}/profile", "users/{id}/profile", map[string]string{
				"id": "",
			}},
			{"path with named regex", "/users/{userId:[0-9]+}/posts", "users/{userId}/posts", map[string]string{
				"userId": "[0-9]+",
			}},
			{"root path", "/", "", emptyMap},
			{
				"path with multiple regexes",
				"/users/{userId:[0-9]+}/posts/{postId:[a-z]+}/[a-z]+/{[0-9]{2}}/[a-z]{10}/abc/{id}/def/[0-9]+",
				fmt.Sprintf(
					"users/{userId}/posts/{postId}/%s/%s/%s/abc/{id}/dev/%s",
					anonRePattern(4),
					anonRePattern(5),
					anonRePattern(6),
					anonRePattern(7),
				),
				map[string]string{
					anonRe(4): "[a-z]+",
					anonRe(5): "[0-9]{2}",
					anonRe(6): "[a-z]{10}",
					anonRe(7): "[0-9]+",
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				nPath, err := parser.Parse(tc.path)
				assert.NoError(t, err)

				assert.Equal(t, tc.expectedIdPrefix, nPath.RawOpIdPrefix())

				resMap := paramsToMapHelper(t, nPath.Parameters())
				assert.Equal(t, tc.expectedParams, resMap)
			})
		}
	})
}

func paramsToMapHelper(t *testing.T, parameters []*openapi3.Parameter) map[string]string {
	m := make(map[string]string, len(parameters))

	for _, p := range parameters {
		_, ok := m[p.Name]
		require.False(t, ok, "parameter %q does not exist", p.Name)
		m[p.Name] = p.Schema.Value.Pattern
	}

	return m
}

func anonRePattern(nr int) string {
	return fmt.Sprintf("{%s}", anonRe(nr))
}

func anonRe(nr int) string {
	return fmt.Sprintf("%s%d", pathnormalizer.RePrefix, nr)
}
