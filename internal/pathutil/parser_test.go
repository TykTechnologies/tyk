package pathutil_test

import (
	"github.com/TykTechnologies/tyk/internal/pathutil"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestParser(t *testing.T) {
	t.Run("positive tests cases common", func(t *testing.T) {
		type testCase struct {
			name             string
			path             string
			expectedIdPrefix string
			expectedParams   map[string]string
		}

		parser := pathutil.NewParser()
		emptyMap := make(map[string]string)

		for _, tc := range []testCase{
			{
				"parses some data",
				"/hello/world",
				"hello/world",
				emptyMap,
			},
			{"removes duplicated slashes", "/hello//world", "hello/world", emptyMap},
			{"leaves trailing slash", "/hello//world//", "hello/world/", emptyMap},
			{"parses anonymous regexp", "/users/[0-9]+", "users/{customRegex1}", map[string]string{
				"customRegex1": "[0-9]+",
			}},
			{"parses anonymous regexp wis trailing slash", "/users/[0-9]+/", "users/{customRegex1}/", map[string]string{
				"customRegex1": "[0-9]+",
			}},
			{"parses mux patterns with label", "/users/{id:[0-9]+}", "users/{id}", map[string]string{
				"id": "[0-9]+",
			}},

			// Edson's test-cases
			{"empty path", "", "", emptyMap},

			// this test is not rfc3986 compatible cause of "/test/.*/end" is valid path
			// but due to historical circumstances it can be treated as regex from old classic api as well
			{"path with regex", "/test/.*/end", "test/{customRegex1}/end", map[string]string{
				"customRegex1": ".*",
			}},
			{"path with curly braces", "/users/{id}/profile", "users/{id}/profile", map[string]string{
				"id": pathutil.DefaultNonDefinedRe,
			}},
			{"path with named regex", "/users/{userId:[0-9]+}/posts", "users/{userId}/posts", map[string]string{
				"userId": "[0-9]+",
			}},
			{"root path", "/", "", emptyMap},
			{
				"path with multiple regexes",
				"/users/{userId:[0-9]+}/posts/{postId:[a-z]+}/[a-z]+/{[0-9]{2}}/[a-z]{10}/abc/{id}/def/[0-9]+",
				"users/{userId}/posts/{postId}/{customRegex1}/{customRegex2}/{customRegex3}/abc/{id}/def/{customRegex4}",
				map[string]string{
					"customRegex1": "[a-z]+",
					"customRegex2": "[0-9]{2}",
					"customRegex3": "[a-z]{10}",
					"customRegex4": "[0-9]+",
					"id":           "",
					"postId":       "[a-z]+",
					"userId":       "[0-9]+",
				},
			},

			{"parses mux patterns without label", "/users/{[0-9]{3}}/", "users/{customRegex1}/", map[string]string{
				"customRegex1": "[0-9]{3}",
			}},

			{"parses mux patterns without label and additional prefix 1", "/users/{prefix[0-9]{1}}/", "users/{customRegex1}/", map[string]string{
				"customRegex1": "prefix[0-9]{1}",
			}},

			{"parses mux patterns without label and additional prefix 2", "/users/prefix[0-9]{2}/", "users/{customRegex1}/", map[string]string{
				"customRegex1": "prefix[0-9]{2}",
			}},

			{"compound re in one path", "/users/[a-z]{10}[0-9]{5}", "users/{customRegex1}", map[string]string{
				"customRegex1": "[a-z]{10}[0-9]{5}",
			}},

			// documentation test cases from (https://tyk.io/docs/getting-started/key-concepts/url-matching/)
			{"test case unknown", "/products/{productId}/reviews/{rating:\\d+}", "products/{productId}/reviews/{rating}", map[string]string{
				"productId": "",
				"rating":    "\\d+",
			}},

			{"must parse named identifier RegExp separated by colon", "/user/id:[0-9]+/accelerate", "user/{id}/accelerate", map[string]string{
				"id": "[0-9]+",
			}},

			// tests for parsing grpc-style paths
			{"grpc service", "/v1.Service", "v1.Service", map[string]string{}},
			{"grpc nested service", "/v1.Service/stats.Service", "v1.Service/stats.Service", map[string]string{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Helper()

				nPath, err := parser.Parse(tc.path)
				assert.NoError(t, err)

				assert.Equal(t, tc.expectedIdPrefix, nPath.RawOpIdPrefix())

				resMap := paramsToMapHelper(t, nPath.Parameters())
				assert.Equal(t, tc.expectedParams, resMap)
			})
		}
	})

	t.Run("global ctr", func(t *testing.T) {
		type testCase struct {
			name             string
			path             string
			expectedIdPrefix string
			expectedParams   map[string]string
		}

		parser := pathutil.NewParser(pathutil.WithGlobalCounter())

		for _, tc := range []testCase{
			{"first case anon RegEx parameter", "/users/[0-9]+", "users/{customRegex1}", map[string]string{
				"customRegex1": "[0-9]+",
			}},
			{"second case anon RegEx parameter", "/users/[a-z]+", "users/{customRegex2}", map[string]string{
				"customRegex2": "[a-z]+",
			}},
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

	t.Run("negative test cases", func(t *testing.T) {
		parser := pathutil.NewParser(pathutil.WithGlobalCounter())

		_, err := parser.Parse("/users/{aaa[0-9]{2}/}")
		assert.ErrorContains(t, err, pathutil.ErrUnexpectedSlash.Error())

		_, err = parser.Parse("/users/aaa[0-9]{2/}")
		assert.ErrorContains(t, err, pathutil.ErrUnexpectedSlash.Error())

		_, err = parser.Parse("/users/{[0-9]{2}}[0-9]{2}")
		assert.ErrorContains(t, err, pathutil.ErrUnexpectedSymbol.Error())
	})
}

func paramsToMapHelper(t *testing.T, parameters []*openapi3.Parameter) map[string]string {
	t.Helper()

	m := make(map[string]string, len(parameters))

	for _, p := range parameters {
		_, ok := m[p.Name]
		assert.False(t, ok, "parameter %q does not exist", p.Name)
		m[p.Name] = p.Schema.Value.Pattern
	}

	return m
}
