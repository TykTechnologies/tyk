package oas

import (
	"context"
	"embed"
	"fmt"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/time"
)

func minimumValidOAS() OAS {
	return OAS{
		T: openapi3.T{
			Info: &openapi3.Info{
				Title:   "title",
				Version: "version",
			},
			OpenAPI: DefaultOpenAPI,
		},
	}
}

//go:embed testdata/urlSorting.json
var urlSortingFS embed.FS

func TestOAS_PathsAndOperations_sorting(t *testing.T) {
	var oasDef OAS
	var classicDef apidef.APIDefinition

	decode(t, urlSortingFS, &oasDef, "testdata/urlSorting.json")

	oasDef.ExtractTo(&classicDef)

	got := []string{}
	for _, v := range classicDef.VersionData.Versions[""].ExtendedPaths.Ignored {
		got = append(got, v.Path)
	}

	want := []string{
		"/test/abc/def",
		"/anything/dupa",
		"/anything/dupe",
		"/anything/dupi",
		"/anything/dupo",
		"/anything/{id}",
		"/test/abc",
		"/test/{id}",
		"/anything",
		"/test",
	}

	assert.Equal(t, want, got)
}

func TestOAS_PathsAndOperations(t *testing.T) {
	t.Parallel()

	const operationId = "userGET"
	const existingOperationId = "userPOST"

	var oas OAS
	oas.Paths = openapi3.Paths{
		"/user": {
			Get: &openapi3.Operation{
				OperationID: operationId,
			},
		},
	}

	var operation Operation
	Fill(t, &operation, 0)
	operation.TrackEndpoint = nil                     // This one also fills native part, let's skip it for this test.
	operation.DoNotTrackEndpoint = nil                // This one also fills native part, let's skip it for this test.
	operation.ValidateRequest = nil                   // This one also fills native part, let's skip it for this test.
	operation.MockResponse = nil                      // This one also fills native part, let's skip it for this test.
	operation.URLRewrite = nil                        // This one also fills native part, let's skip it for this test.
	operation.Internal = nil                          // This one also fills native part, let's skip it for this test.
	operation.TransformRequestBody.Path = ""          // if `path` and `body` are present, `body` would take precedence, detailed tests can be found in middleware_test.go
	operation.TransformResponseBody.Path = ""         // if `path` and `body` are present, `body` would take precedence, detailed tests can be found in middleware_test.go
	operation.VirtualEndpoint.Path = ""               // if `path` and `body` are present, `body` would take precedence, detailed tests can be found in middleware_test.go
	operation.VirtualEndpoint.Name = ""               // Name is deprecated.
	operation.PostPlugins = operation.PostPlugins[:1] // only 1 post plugin is considered at this point, ignore others.
	operation.PostPlugins[0].Name = ""                // Name is deprecated.

	operation.RateLimit.Per = ReadableDuration(time.Minute)

	xTykAPIGateway := &XTykAPIGateway{
		Middleware: &Middleware{
			Operations: Operations{
				operationId: &operation,
			},
		},
	}

	oas.SetTykExtension(xTykAPIGateway)

	var ep apidef.ExtendedPathsSet
	oas.extractPathsAndOperations(&ep)

	convertedOAS := minimumValidOAS()
	convertedOAS.Paths = openapi3.Paths{
		"/user": {
			Post: &openapi3.Operation{
				OperationID: existingOperationId,
				Responses:   openapi3.NewResponses(),
			},
		},
	}
	convertedOAS.SetTykExtension(&XTykAPIGateway{Middleware: &Middleware{Operations: Operations{}}})
	convertedOAS.fillPathsAndOperations(ep)

	assert.Equal(t, oas.getTykOperations(), convertedOAS.getTykOperations())

	expCombinedPaths := openapi3.Paths{
		"/user": {
			Post: &openapi3.Operation{
				OperationID: existingOperationId,
				Responses:   openapi3.NewResponses(),
			},
			Get: &openapi3.Operation{
				OperationID: operationId,
				Responses:   openapi3.NewResponses(),
			},
		},
	}

	assert.Equal(t, expCombinedPaths, convertedOAS.Paths)

	t.Run("oas validation", func(t *testing.T) {
		err := convertedOAS.Validate(context.Background())
		assert.NoError(t, err)
	})
}

func TestOAS_PathsAndOperationsRegex(t *testing.T) {
	t.Parallel()

	expectedOperationID := "users/[a-z]+/[0-9]+$GET"
	expectedPath := "/users/{customRegex1}/{customRegex2}"

	var oas OAS
	oas.Paths = openapi3.Paths{}

	_ = oas.getOperationID("/users/[a-z]+/[0-9]+$", "GET")

	expectedPathItems := openapi3.Paths{
		expectedPath: &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: expectedOperationID,
				Responses:   openapi3.NewResponses(),
			},
			Parameters: []*openapi3.ParameterRef{
				{
					Value: &openapi3.Parameter{
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:    "string",
								Pattern: "[a-z]+",
							},
						},
						Name:     "customRegex1",
						In:       "path",
						Required: true,
					},
				},
				{
					Value: &openapi3.Parameter{
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:    "string",
								Pattern: "[0-9]+$",
							},
						},
						Name:     "customRegex2",
						In:       "path",
						Required: true,
					},
				},
			},
		},
	}

	assert.Equal(t, expectedPathItems, oas.Paths, "expected path item differs")
}

func TestOAS_RegexOperationIDs(t *testing.T) {
	t.Parallel()

	type test struct {
		input  string
		method string
		want   string
	}

	tests := []test{
		{"/.+", "GET", ".+GET"},
		{"/.*", "GET", ".*GET"},
		{"/[^a]*", "GET", "[^a]*GET"},
		{"/foo$", "GET", "foo$GET"},
		{"/group/.+", "GET", "group/.+GET"},
		{"/group/.*", "GET", "group/.*GET"},
		{"/group/[^a]*", "GET", "group/[^a]*GET"},
		{"/group/foo$", "GET", "group/foo$GET"},
		{"/group/[^a]*/.*", "GET", "group/[^a]*/.*GET"},
	}

	for i, tc := range tests {
		var oas OAS
		oas.Paths = openapi3.Paths{
			tc.input: {
				Get: &openapi3.Operation{},
			},
		}
		got := oas.getOperationID(tc.input, tc.method)
		assert.Equalf(t, tc.want, got, "test %d: expected operationID %v, got %v", i, tc.want, got)
	}
}

func TestOAS_RegexPaths(t *testing.T) {
	t.Parallel()

	type test struct {
		input  string
		want   string
		params []string
	}

	tests := []test{
		{"/v1.Service", "/v1.Service", []string{}},
		{"/v1.Service/stats.Service", "/v1.Service/stats.Service", []string{}},
		{"/users/documents/list", "/users/documents/list", []string{}},
		{"/group/.+", "/group/{customRegex1}", []string{"customRegex1"}},
		{"/group/.*", "/group/{customRegex1}", []string{"customRegex1"}},
		{"/group/[^a]*", "/group/{customRegex1}", []string{"customRegex1"}},
		{"/group/foo$", "/group/{customRegex1}", []string{"customRegex1"}},
		{"/group/[^a]*/.*", "/group/{customRegex1}/{customRegex2}", []string{"customRegex1", "customRegex2"}},
		{"/users/documents/list", "/users/documents/list", []string{}},
		{"/users/{id}/profile", "/users/{id}/profile", []string{"id"}},
		{"/users/{id:[0-9]+}/profile", "/users/{id}/profile", []string{"id"}},
		{"/files/{.*}/download", "/files/{customRegex1}/download", []string{"customRegex1"}},
		{"/{id:[0-9]+}/{name:[a-zA-Z]+}/{.*}", "/{id}/{name}/{customRegex1}", []string{"id", "name", "customRegex1"}},
		{"", "", []string{}},
		{"/", "/", []string{}},
		{"/users/profile/", "/users/profile/", []string{}},
		{"/dates/{date:[0-9]{4}-[0-9]{2}-[0-9]{2}}/events", "/dates/{date}/events", []string{"date"}},
		{"/.+", "/{customRegex1}", []string{"customRegex1"}},
		{"/.+/", "/{customRegex1}/", []string{"customRegex1"}},
		{"/users/my-profile/", "/users/my-profile/", []string{}},
		{"/[0-9]+/[a-zA-Z]+/.*", "/{customRegex1}/{customRegex2}/{customRegex3}", []string{"customRegex1", "customRegex2", "customRegex3"}},
	}

	for i, tc := range tests {
		var oas OAS
		oas.Paths = openapi3.Paths{}
		_ = oas.getOperationID(tc.input, "GET")

		pathKeys := make([]string, 0, len(oas.Paths))
		for k := range oas.Paths {
			pathKeys = append(pathKeys, k)
		}

		assert.Lenf(t, oas.Paths, 1, "Expected one path key being created, got %#v", pathKeys)
		_, ok := oas.Paths[tc.want]
		assert.True(t, ok)

		p, ok := oas.Paths[tc.want]
		assert.Truef(t, ok, "test %d: path doesn't exist in OAS: %v", i, tc.want)
		assert.Lenf(t, p.Parameters, len(tc.params), "test %d: expected %d parameters, got %d", i, len(tc.params), len(p.Parameters))

		extractedParams := make([]string, 0, len(p.Parameters))
		for _, param := range p.Parameters {
			if param.Value == nil {
				continue
			}

			if param.Value.Schema == nil {
				continue
			}

			if param.Value.Schema.Value == nil {
				continue
			}

			extractedParams = append(extractedParams, param.Value.Name)
		}

		assert.ElementsMatch(t, tc.params, extractedParams)

		// rebuild original link
		got := tc.want
		for _, param := range p.Parameters {
			require.NotNilf(t, param.Value, "test %d: missing value", i)
			require.NotNilf(t, param.Value.Schema, "test %d: missing schema", i)
			require.NotNilf(t, param.Value.Schema.Value, "test %d: missing schema value", i)

			paramName := "{" + param.Value.Name + "}"
			if param.Value.Schema.Value.Pattern == "" {
				continue
			}

			pattern := param.Value.Schema.Value.Pattern
			isNamedParam := isParamName(param.Value.Name) && !strings.HasPrefix(param.Value.Name, "customRegex")
			hasBraces := false
			for _, part := range strings.Split(tc.input, "/") {
				if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
					hasBraces = true
					break
				}
			}

			switch {
			case isNamedParam:
				// For named parameters like "id", use {id:pattern} format
				got = strings.ReplaceAll(got, paramName, fmt.Sprintf("{%s:%s}", param.Value.Name, pattern))
			case hasBraces:
				// If original input used braces, maintain them
				got = strings.ReplaceAll(got, paramName, "{"+pattern+"}")
			default:
				// Otherwise use the pattern directly
				got = strings.ReplaceAll(got, paramName, pattern)
			}
		}

		assert.Equalf(t, tc.input, got, "test %d: rebuilt link, expected %v, got %v", i, tc.input, got)
	}
}

func TestPathPartString(t *testing.T) {
	tests := []struct {
		name     string
		pathPart pathPart
		want     string
	}{
		{
			name: "regular path part",
			pathPart: pathPart{
				name:    "users",
				value:   "users",
				isRegex: false,
			},
			want: "users",
		},
		{
			name: "regex path part",
			pathPart: pathPart{
				name:    "customRegex1",
				value:   ".*",
				isRegex: true,
			},
			want: "{customRegex1}",
		},
		{
			name: "named pattern format",
			pathPart: pathPart{
				name:    "id",
				value:   "[0-9]+",
				isRegex: true,
			},
			want: "{id}",
		},
		{
			name: "named pattern with multiple colons",
			pathPart: pathPart{
				name:    "path",
				value:   ".*:more:stuff",
				isRegex: true,
			},
			want: "{path}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pathPart.String()
			if got != tt.want {
				t.Errorf("pathPart.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		expectedParts []pathPart
		expectedRegex bool
	}{
		{
			name: "standard path without regex",
			path: "/users/documents/list",
			expectedParts: []pathPart{
				{name: "users", value: "users", isRegex: false},
				{name: "documents", value: "documents", isRegex: false},
				{name: "list", value: "list", isRegex: false},
			},
			expectedRegex: false,
		},
		{
			name: "path with named parameter",
			path: "/users/{id}/profile",
			expectedParts: []pathPart{
				{name: "users", value: "users", isRegex: false},
				{name: "id", value: "", isRegex: false},
				{name: "profile", value: "profile", isRegex: false},
			},
			expectedRegex: true,
		},
		{
			name: "path with regex pattern",
			path: "/users/{id:[0-9]+}/profile",
			expectedParts: []pathPart{
				{name: "users", value: "users", isRegex: false},
				{name: "id", value: "[0-9]+", isRegex: true},
				{name: "profile", value: "profile", isRegex: false},
			},
			expectedRegex: true,
		},
		{
			name: "path with direct regex",
			path: "/files/{.*}/download",
			expectedParts: []pathPart{
				{name: "files", value: "files", isRegex: false},
				{name: "customRegex1", value: ".*", isRegex: true},
				{name: "download", value: "download", isRegex: false},
			},
			expectedRegex: true,
		},
		{
			name: "path with multiple regex patterns",
			path: "/{id:[0-9]+}/{name:[a-zA-Z]+}/{.*}",
			expectedParts: []pathPart{
				{name: "id", value: "[0-9]+", isRegex: true},
				{name: "name", value: "[a-zA-Z]+", isRegex: true},
				{name: "customRegex1", value: ".*", isRegex: true},
			},
			expectedRegex: true,
		},
		{
			name: "path with invalid parameter names",
			path: "/users/{123}/{user-name}",
			expectedParts: []pathPart{
				{name: "users", value: "users", isRegex: false},
				{name: "customRegex1", value: "123", isRegex: true},
				{name: "customRegex2", value: "user-name", isRegex: true},
			},
			expectedRegex: true,
		},
		{
			name: "path with invalid starting character",
			path: "/users/{1invalid}",
			expectedParts: []pathPart{
				{name: "users", value: "users", isRegex: false},
				{name: "customRegex1", value: "1invalid", isRegex: true},
			},
			expectedRegex: true,
		},
		{
			name:          "empty path",
			path:          "",
			expectedParts: []pathPart{},
			expectedRegex: false,
		},
		{
			name:          "root path",
			path:          "/",
			expectedParts: []pathPart{},
			expectedRegex: false,
		},
		{
			name: "path with trailing slash",
			path: "/users/profile/",
			expectedParts: []pathPart{
				{name: "users", value: "users", isRegex: false},
				{name: "profile", value: "profile", isRegex: false},
			},
			expectedRegex: false,
		},
		{
			name: "path with complex regex pattern",
			path: "/dates/{date:[0-9]{4}-[0-9]{2}-[0-9]{2}}/events",
			expectedParts: []pathPart{
				{name: "dates", value: "dates", isRegex: false},
				{name: "date", value: "[0-9]{4}-[0-9]{2}-[0-9]{2}", isRegex: true},
				{name: "events", value: "events", isRegex: false},
			},
			expectedRegex: true,
		},
		{
			name: "root regex pattern",
			path: "/.+",
			expectedParts: []pathPart{
				{name: "customRegex1", value: ".+", isRegex: true},
			},
			expectedRegex: true,
		},
		{
			name: "root regex pattern with trailing slash",
			path: "/.+",
			expectedParts: []pathPart{
				{name: "customRegex1", value: ".+", isRegex: true},
			},
			expectedRegex: true,
		},
		{
			name: "path with trailing slash",
			path: "/users/my-profile/",
			expectedParts: []pathPart{
				{name: "users", value: "users", isRegex: false},
				{name: "my-profile", value: "my-profile", isRegex: false},
			},
			expectedRegex: false,
		},
		{
			name: "path with multiple regex patterns",
			path: "/[0-9]+/[a-zA-Z]+/.*",
			expectedParts: []pathPart{
				{name: "customRegex1", value: "[0-9]+", isRegex: true},
				{name: "customRegex2", value: "[a-zA-Z]+", isRegex: true},
				{name: "customRegex3", value: ".*", isRegex: true},
			},
			expectedRegex: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, hasRegex := splitPath(tt.path)

			if hasRegex != tt.expectedRegex {
				t.Errorf("splitPath() hasRegex = %v, want %v", hasRegex, tt.expectedRegex)
			}

			if len(parts) != len(tt.expectedParts) {
				t.Errorf("splitPath() returned %d parts, want %d", len(parts), len(tt.expectedParts))
				return
			}

			for i, part := range parts {
				expected := tt.expectedParts[i]
				if part.name != expected.name {
					t.Errorf("Part %d name = %v, want %v", i, part.name, expected.name)
				}
				if part.value != expected.value {
					t.Errorf("Part %d value = %v, want %v", i, part.value, expected.value)
				}
				if part.isRegex != expected.isRegex {
					t.Errorf("Part %d isRegex = %v, want %v", i, part.isRegex, expected.isRegex)
				}
			}
		})
	}
}
