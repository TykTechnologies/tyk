package oasutil

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func testOASPaths(paths []string) openapi3.Paths {
	result := openapi3.NewPaths()
	for _, p := range paths {
		result.Set(p, nil)
	}
	return *result
}

// TestSortByPathLength tests our custom sorting for the OAS paths.
func TestSortByPathLength(t *testing.T) {
	want := []string{
		"/test/{id}/asset",
		"/test/{id}/{file}",
		"/test/sub1",
		"/test/sub2",
		"/test/sub",
		"/test/sub{id}",
		"/test/a",
		"/test/b",
		"/test/c",
		"/test/{id}",
		"/test",
	}

	want = []string{
		"/test/abc/def",
		"/anything/dupa",
		"/anything/{id}",
		"/test/abc",
		"/test/{id}",
		"/anything",
		"/test",
	}

	paths := testOASPaths(want)

	out := SortByPathLength(paths)

	got := []string{}
	for _, v := range out {
		got = append(got, v.Path)
	}

	assert.Equal(t, want, got, "got %#v", got)
}

// TestExtractPath uses the upstream library to extract an ordered list of paths.
func TestExtractPaths(t *testing.T) {
	want := []string{
		"/test/sub2",
		"/test/sub1",
		"/test/sub",
		"/test/c",
		"/test/b",
		"/test/a",
		"/test",
		"/test/{id}/asset",
		"/test/{id}",
		"/test/sub{id}", // this is problematic, should be one line up
		"/test/{id}/{file}",
	}

	paths := testOASPaths(want)

	order := paths.InMatchingOrder()

	out := ExtractPaths(paths, order)

	got := []string{}
	for _, v := range out {
		got = append(got, v.Path)
	}

	assert.Equal(t, want, got)
}

func TestPathToRegex(t *testing.T) {
	typeString := openapi3.Types{"string"}
	typeInteger := openapi3.Types{"integer"}

	params := openapi3.Parameters{
		&openapi3.ParameterRef{
			Value: &openapi3.Parameter{
				Name: "id",
				Schema: &openapi3.SchemaRef{
					Value: &openapi3.Schema{
						Type: &typeInteger,
					},
				},
			},
		},
		&openapi3.ParameterRef{
			Value: &openapi3.Parameter{
				Name: "name",
				Schema: &openapi3.SchemaRef{
					Value: &openapi3.Schema{
						Type:    &typeString,
						Pattern: "^[a-zA-Z]+$",
					},
				},
			},
		},
		&openapi3.ParameterRef{
			Value: &openapi3.Parameter{
				Name: "file",
				Schema: &openapi3.SchemaRef{
					Value: &openapi3.Schema{
						Type:    &typeString,
						Pattern: `\w+\.pdf`,
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "Type fallback parsing without capture groups",
			path:     "/user/{id}",
			expected: `/user/[-+]?\d+`,
		},
		{
			name:     "Explicit pattern with anchors stripped",
			path:     "/user/{id}/names/{name}",
			expected: `/user/[-+]?\d+/names/[a-zA-Z]+`,
		},
		{
			name:     "Explicit pattern without anchors",
			path:     "/downloads/{file}",
			expected: `/downloads/\w+\.pdf`,
		},
		{
			name:     "Unknown parameter defaults to catch-all",
			path:     "/items/{unknown}",
			expected: `/items/[^/]+`,
		},
		{
			name:     "Multiple identical parameters",
			path:     "/compare/{id}/with/{id}",
			expected: `/compare/[-+]?\d+/with/[-+]?\d+`,
		},
		{
			name:     "Static path with no parameters",
			path:     "/health/check",
			expected: `/health/check`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := PathToRegex(tt.path, params)
			if actual != tt.expected {
				t.Errorf("PathToRegex() = %q, want %q", actual, tt.expected)
			}
		})
	}
}

func TestGetParamDetails(t *testing.T) {
	// Helper variables for OpenAPI 3.1 Types slice
	typeString := openapi3.Types{"string"}
	typeInteger := openapi3.Types{"integer"}

	tests := []struct {
		name        string
		params      openapi3.Parameters
		paramName   string
		wantType    string
		wantPattern string
	}{
		{
			name:        "Schema defines both Type and Pattern",
			paramName:   "userId",
			wantType:    "string",
			wantPattern: `^[a-zA-Z0-9]+$`,
			params: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name: "userId",
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:    &typeString,
								Pattern: `^[a-zA-Z0-9]+$`,
							},
						},
					},
				},
			},
		},
		{
			name:        "Schema defines Type but no Pattern",
			paramName:   "page",
			wantType:    "integer",
			wantPattern: "",
			params: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name: "page",
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &typeInteger,
							},
						},
					},
				},
			},
		},
		{
			name:        "Content defines Type and Pattern (Edge Case)",
			paramName:   "filter",
			wantType:    "string",
			wantPattern: `^\w+$`,
			params: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name: "filter",
						Content: openapi3.Content{
							"application/json": &openapi3.MediaType{
								Schema: &openapi3.SchemaRef{
									Value: &openapi3.Schema{
										Type:    &typeString,
										Pattern: `^\w+$`,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:        "Parameter not found in array",
			paramName:   "unknownParam",
			wantType:    "",
			wantPattern: "",
			params: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name: "userId",
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &typeInteger,
							},
						},
					},
				},
			},
		},
		{
			name:        "Safely handles nil references and values",
			paramName:   "userId",
			wantType:    "",
			wantPattern: "",
			params: openapi3.Parameters{
				nil,
				&openapi3.ParameterRef{Value: nil},
			},
		},
		{
			name:        "Parameter found but Schema is completely empty",
			paramName:   "emptyParam",
			wantType:    "",
			wantPattern: "",
			params: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name: "emptyParam",
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotPattern := GetParamDetails(tt.params, tt.paramName)

			if gotType != tt.wantType {
				t.Errorf("GetParamDetails() gotType = %q, want %q", gotType, tt.wantType)
			}
			if gotPattern != tt.wantPattern {
				t.Errorf("GetParamDetails() gotPattern = %q, want %q", gotPattern, tt.wantPattern)
			}
		})
	}
}
