package oas

import (
	"context"
	"embed"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

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

func TestOAS_MockResponse(t *testing.T) {
	t.Parallel()

	// Test case 1: Basic mock response
	t.Run("basic mock response", func(t *testing.T) {
		spec := OAS{
			T: openapi3.T{
				OpenAPI: DefaultOpenAPI,
				Paths: openapi3.Paths{
					"/test": {
						Get: &openapi3.Operation{
							OperationID: "testGET",
						},
					},
				},
				Extensions: map[string]interface{}{
					"x-tyk-api-gateway": &XTykAPIGateway{
						Middleware: &Middleware{
							Operations: Operations{
								"testGET": &Operation{
									MockResponse: &MockResponse{
										Enabled: true,
										Code:    200,
										Body:    `{"message": "success"}`,
										Headers: []Header{
											{
												Name:  "Content-Type",
												Value: "application/json",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		var ep apidef.ExtendedPathsSet
		spec.extractPathsAndOperations(&ep)

		// Verify the mock response was correctly extracted
		assert.Len(t, ep.MockResponse, 1)
		mockResp := ep.MockResponse[0]
		assert.Equal(t, "/test", mockResp.Path)
		assert.Equal(t, "GET", mockResp.Method)
		assert.Equal(t, 200, mockResp.Code)
		assert.Equal(t, `{"message": "success"}`, mockResp.Body)
		assert.Equal(t, map[string]string{"Content-Type": "application/json"}, mockResp.Headers)
		assert.False(t, mockResp.Disabled)
	})

	// Test case 2: Multiple mock responses
	t.Run("multiple mock responses", func(t *testing.T) {
		spec := OAS{
			T: openapi3.T{
				OpenAPI: DefaultOpenAPI,
				Paths: openapi3.Paths{
					"/test": {
						Get: &openapi3.Operation{
							OperationID: "testGET",
						},
						Post: &openapi3.Operation{
							OperationID: "testPOST",
						},
					},
				},
				Extensions: map[string]interface{}{
					"x-tyk-api-gateway": &XTykAPIGateway{
						Middleware: &Middleware{
							Operations: Operations{
								"testGET": &Operation{
									MockResponse: &MockResponse{
										Enabled: true,
										Code:    200,
										Body:    `{"status": "ok"}`,
										Headers: []Header{
											{Name: "Content-Type", Value: "application/json"},
										},
									},
								},
								"testPOST": &Operation{
									MockResponse: &MockResponse{
										Enabled: true,
										Code:    201,
										Body:    `{"id": "123"}`,
										Headers: []Header{
											{Name: "Content-Type", Value: "application/json"},
											{Name: "Location", Value: "/test/123"},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		var ep apidef.ExtendedPathsSet
		spec.extractPathsAndOperations(&ep)

		// Verify multiple mock responses were correctly extracted
		assert.Len(t, ep.MockResponse, 2)

		// Sort mock responses by path+method for consistent testing
		sort.Slice(ep.MockResponse, func(i, j int) bool {
			if ep.MockResponse[i].Path == ep.MockResponse[j].Path {
				return ep.MockResponse[i].Method < ep.MockResponse[j].Method
			}
			return ep.MockResponse[i].Path < ep.MockResponse[j].Path
		})

		// Verify GET mock response
		getMock := ep.MockResponse[0]
		assert.Equal(t, "/test", getMock.Path)
		assert.Equal(t, "GET", getMock.Method)
		assert.Equal(t, 200, getMock.Code)
		assert.Equal(t, `{"status": "ok"}`, getMock.Body)
		assert.Equal(t, map[string]string{"Content-Type": "application/json"}, getMock.Headers)
		assert.False(t, getMock.Disabled)

		// Verify POST mock response
		postMock := ep.MockResponse[1]
		assert.Equal(t, "/test", postMock.Path)
		assert.Equal(t, "POST", postMock.Method)
		assert.Equal(t, 201, postMock.Code)
		assert.Equal(t, `{"id": "123"}`, postMock.Body)
		assert.Equal(t, map[string]string{
			"Content-Type": "application/json",
			"Location":     "/test/123",
		}, postMock.Headers)
		assert.False(t, postMock.Disabled)
	})

	// Test case 3: Disabled mock response
	t.Run("disabled mock response", func(t *testing.T) {
		spec := OAS{
			T: openapi3.T{
				OpenAPI: DefaultOpenAPI,
				Paths: openapi3.Paths{
					"/test": {
						Get: &openapi3.Operation{
							OperationID: "testGET",
						},
					},
				},
				Extensions: map[string]interface{}{
					"x-tyk-api-gateway": &XTykAPIGateway{
						Middleware: &Middleware{
							Operations: Operations{
								"testGET": &Operation{
									MockResponse: &MockResponse{
										Enabled: false,
										Code:    404,
										Body:    `{"error": "not found"}`,
									},
								},
							},
						},
					},
				},
			},
		}

		var ep apidef.ExtendedPathsSet
		spec.extractPathsAndOperations(&ep)

		// Verify disabled mock response was correctly extracted
		assert.Len(t, ep.MockResponse, 1)
		mockResp := ep.MockResponse[0]
		assert.Equal(t, "/test", mockResp.Path)
		assert.Equal(t, "GET", mockResp.Method)
		assert.Equal(t, 404, mockResp.Code)
		assert.Equal(t, `{"error": "not found"}`, mockResp.Body)
		assert.True(t, mockResp.Disabled)
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
		params int
	}

	tests := []test{
		{"/v1.Service", "/v1.Service", 0},
		{"/v1.Service/stats.Service", "/v1.Service/stats.Service", 0},
		{"/.+", "/{customRegex1}", 1},
		{"/.*", "/{customRegex1}", 1},
		{"/[^a]*", "/{customRegex1}", 1},
		{"/foo$", "/{customRegex1}", 1},
		{"/group/.+", "/group/{customRegex1}", 1},
		{"/group/.*", "/group/{customRegex1}", 1},
		{"/group/[^a]*", "/group/{customRegex1}", 1},
		{"/group/foo$", "/group/{customRegex1}", 1},
		{"/group/[^a]*/.*", "/group/{customRegex1}/{customRegex2}", 2},
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
		assert.Lenf(t, p.Parameters, tc.params, "test %d: expected %d parameters, got %d", i, tc.params, len(p.Parameters))

		// rebuild original link
		got := tc.want
		for _, param := range p.Parameters {
			assert.NotNilf(t, param.Value, "test %d: missing value", i)
			assert.NotNilf(t, param.Value.Schema, "test %d: missing schema", i)
			assert.NotNilf(t, param.Value.Schema.Value, "test %d: missing schema value", i)

			assert.Truef(t, strings.HasPrefix(param.Value.Name, "customRegex"), "test %d: invalid name %v", i, param.Value.Name)

			got = strings.ReplaceAll(got, "{"+param.Value.Name+"}", param.Value.Schema.Value.Pattern)
		}

		assert.Equalf(t, tc.input, got, "test %d: rebuilt link, expected %v, got %v", i, tc.input, got)
	}
}

func TestMockResponse_Fill(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		meta apidef.MockResponseMeta
		want MockResponse
	}{
		{
			name: "basic mock response",
			meta: apidef.MockResponseMeta{
				Path:     "/test",
				Method:   "GET",
				Code:     200,
				Body:     `{"message": "success"}`,
				Headers:  map[string]string{"Content-Type": "application/json"},
				Disabled: false,
			},
			want: MockResponse{
				Enabled: true,
				Code:    200,
				Body:    `{"message": "success"}`,
				Headers: []Header{
					{
						Name:  "Content-Type",
						Value: "application/json",
					},
				},
			},
		},
		{
			name: "disabled mock response",
			meta: apidef.MockResponseMeta{
				Path:     "/test",
				Method:   "GET",
				Code:     404,
				Body:     `{"error": "not found"}`,
				Headers:  map[string]string{"X-Error": "true"},
				Disabled: true,
			},
			want: MockResponse{
				Enabled: false,
				Code:    404,
				Body:    `{"error": "not found"}`,
				Headers: []Header{
					{
						Name:  "X-Error",
						Value: "true",
					},
				},
			},
		},
		{
			name: "empty headers",
			meta: apidef.MockResponseMeta{
				Path:     "/test",
				Method:   "GET",
				Code:     204,
				Body:     "",
				Headers:  nil,
				Disabled: false,
			},
			want: MockResponse{
				Enabled: true,
				Code:    204,
				Body:    "",
				Headers: []Header{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &MockResponse{}
			got.Fill(tt.meta)
			assert.Equal(t, tt.want, *got)
		})
	}
}

func TestMockResponse_ExtractTo(t *testing.T) {
	tests := []struct {
		name string
		mock MockResponse
		want apidef.MockResponseMeta
	}{
		{
			name: "empty mock response",
			mock: MockResponse{},
			want: apidef.MockResponseMeta{
				Disabled: true,
			},
		},
		{
			name: "enabled mock response with all fields",
			mock: MockResponse{
				Enabled: true,
				Code:    201,
				Body:    `{"message": "created"}`,
				Headers: []Header{
					{Name: "Content-Type", Value: "application/json"},
					{Name: "X-Custom", Value: "test"},
				},
			},
			want: apidef.MockResponseMeta{
				Disabled: false,
				Code:     201,
				Body:     `{"message": "created"}`,
				Headers: map[string]string{
					"Content-Type": "application/json",
					"X-Custom":     "test",
				},
			},
		},
		{
			name: "disabled mock response with headers",
			mock: MockResponse{
				Enabled: false,
				Headers: []Header{
					{Name: "X-Test", Value: "value"},
				},
			},
			want: apidef.MockResponseMeta{
				Disabled: true,
				Headers: map[string]string{
					"X-Test": "value",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &apidef.MockResponseMeta{}
			tt.mock.ExtractTo(got)

			if got.Disabled != tt.want.Disabled {
				t.Errorf("MockResponse.ExtractTo() Disabled = %v, want %v", got.Disabled, tt.want.Disabled)
			}

			if got.Code != tt.want.Code {
				t.Errorf("MockResponse.ExtractTo() Code = %v, want %v", got.Code, tt.want.Code)
			}

			if got.Body != tt.want.Body {
				t.Errorf("MockResponse.ExtractTo() Body = %v, want %v", got.Body, tt.want.Body)
			}

			if !reflect.DeepEqual(got.Headers, tt.want.Headers) {
				t.Errorf("MockResponse.ExtractTo() Headers = %v, want %v", got.Headers, tt.want.Headers)
			}
		})
	}
}

func TestOperation_ExtractTo(t *testing.T) {
	tests := []struct {
		name     string
		input    *Operation
		expected apidef.MockResponseMeta
	}{
		{
			name: "basic mock response",
			input: &Operation{
				MockResponse: &MockResponse{
					Enabled: true,
					Code:    200,
					Body:    `{"message": "success"}`,
					Headers: []Header{
						{Name: "Content-Type", Value: "application/json"},
						{Name: "X-Custom", Value: "test"},
					},
				},
			},
			expected: apidef.MockResponseMeta{
				Disabled: false,
				Code:     200,
				Body:     `{"message": "success"}`,
				Headers: map[string]string{
					"Content-Type": "application/json",
					"X-Custom":     "test",
				},
			},
		},
		{
			name: "disabled mock response",
			input: &Operation{
				MockResponse: &MockResponse{
					Enabled: false,
					Code:    404,
					Body:    `{"error": "not found"}`,
					Headers: []Header{
						{Name: "Content-Type", Value: "application/json"},
					},
				},
			},
			expected: apidef.MockResponseMeta{
				Disabled: true,
				Code:     404,
				Body:     `{"error": "not found"}`,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
		},
		{
			name: "empty headers",
			input: &Operation{
				MockResponse: &MockResponse{
					Enabled: true,
					Code:    204,
					Body:    "",
					Headers: nil,
				},
			},
			expected: apidef.MockResponseMeta{
				Disabled: false,
				Code:     204,
				Body:     "",
				Headers:  map[string]string{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &apidef.MockResponseMeta{}
			tc.input.ExtractTo(result)

			// Compare the results
			assert.Equal(t, tc.expected.Disabled, result.Disabled)
			assert.Equal(t, tc.expected.Code, result.Code)
			assert.Equal(t, tc.expected.Body, result.Body)
			assert.Equal(t, tc.expected.Headers, result.Headers)
		})
	}
}

func TestOperations_ExtractTo(t *testing.T) {
	t.Run("should extract mock responses correctly", func(t *testing.T) {
		// Setup test operations
		ops := Operations{
			"/test": {
				MockResponse: &MockResponse{
					Enabled: true,
					Code:    200,
					Body:    "test body",
					Headers: Headers{
						{Name: "Content-Type", Value: "application/json"},
						{Name: "X-Test", Value: "test-value"},
					},
				},
			},
			"/no-mock": {
				// Operation without mock response
				Allow: &Allowance{},
			},
		}

		// Create API definition to extract into
		api := &apidef.APIDefinition{
			VersionData: apidef.VersionData{
				Versions: map[string]apidef.VersionInfo{
					Main: {
						ExtendedPaths: apidef.ExtendedPathsSet{
							// Existing mock responses should be preserved
							MockResponse: []apidef.MockResponseMeta{
								{
									Path:     "/existing",
									Code:     201,
									Body:     "existing body",
									Headers:  map[string]string{"X-Existing": "value"},
									Disabled: true,
								},
							},
						},
					},
				},
			},
		}

		// Execute
		ops.ExtractTo(api)

		// Verify results
		mockResponses := api.VersionData.Versions[Main].ExtendedPaths.MockResponse
		assert.Len(t, mockResponses, 2) // Should have both existing and new mock responses

		// Find and verify the extracted mock response
		var found bool
		for _, mr := range mockResponses {
			if mr.Path == "/test" {
				found = true
				assert.Equal(t, 200, mr.Code)
				assert.Equal(t, "test body", mr.Body)
				assert.Equal(t, false, mr.Disabled) // Enabled = true -> Disabled = false
				assert.Equal(t, map[string]string{
					"Content-Type": "application/json",
					"X-Test":       "test-value",
				}, mr.Headers)
				break
			}
		}
		assert.True(t, found, "Expected to find extracted mock response for /test path")

		// Verify the existing mock response is preserved
		found = false
		for _, mr := range mockResponses {
			if mr.Path == "/existing" {
				found = true
				assert.Equal(t, 201, mr.Code)
				assert.Equal(t, "existing body", mr.Body)
				assert.Equal(t, true, mr.Disabled)
				assert.Equal(t, map[string]string{"X-Existing": "value"}, mr.Headers)
				break
			}
		}
		assert.True(t, found, "Expected to find existing mock response")
	})

	t.Run("should handle nil mock responses", func(t *testing.T) {
		ops := Operations{
			"/test": {
				MockResponse: nil,
			},
		}

		api := &apidef.APIDefinition{
			VersionData: apidef.VersionData{
				Versions: map[string]apidef.VersionInfo{
					Main: {
						ExtendedPaths: apidef.ExtendedPathsSet{},
					},
				},
			},
		}

		ops.ExtractTo(api)

		mockResponses := api.VersionData.Versions[Main].ExtendedPaths.MockResponse
		assert.Empty(t, mockResponses, "Expected no mock responses to be extracted")
	})
}

func TestOperation_Fill(t *testing.T) {
	tests := []struct {
		name string
		op   apidef.MockResponseMeta
		want *Operation
	}{
		{
			name: "empty mock response",
			op:   apidef.MockResponseMeta{},
			want: &Operation{
				MockResponse: &MockResponse{
					Enabled: true,
					Headers: []Header{},
				},
				IgnoreAuthentication: &Allowance{
					Enabled: true,
				},
			},
		},
		{
			name: "mock response with headers",
			op: apidef.MockResponseMeta{
				Disabled: true,
				Code:     404,
				Body:     `{"error": "not found"}`,
				Headers: map[string]string{
					"Content-Type": "application/json",
					"X-Custom":     "value",
				},
			},
			want: &Operation{
				MockResponse: &MockResponse{
					Enabled: false,
					Code:    404,
					Body:    `{"error": "not found"}`,
					Headers: []Header{
						{Name: "Content-Type", Value: "application/json"},
						{Name: "X-Custom", Value: "value"},
					},
				},
				IgnoreAuthentication: &Allowance{
					Enabled: true,
				},
			},
		},
		{
			name: "enabled mock response with no headers",
			op: apidef.MockResponseMeta{
				Disabled: false,
				Code:     201,
				Body:     `{"status": "created"}`,
			},
			want: &Operation{
				MockResponse: &MockResponse{
					Enabled: true,
					Code:    201,
					Body:    `{"status": "created"}`,
					Headers: []Header{},
				},
				IgnoreAuthentication: &Allowance{
					Enabled: true,
				},
			},
		},
		{
			name: "mock response with special characters in body",
			op: apidef.MockResponseMeta{
				Code: 200,
				Body: `{"special": "chars: \n \t \"quoted\""}`,
				Headers: map[string]string{
					"Content-Type": "application/json; charset=utf-8",
				},
			},
			want: &Operation{
				MockResponse: &MockResponse{
					Enabled: true,
					Code:    200,
					Body:    `{"special": "chars: \n \t \"quoted\""}`,
					Headers: []Header{
						{Name: "Content-Type", Value: "application/json; charset=utf-8"},
					},
				},
				IgnoreAuthentication: &Allowance{
					Enabled: true,
				},
			},
		},
		{
			name: "mock response with multiple headers",
			op: apidef.MockResponseMeta{
				Code: 307,
				Headers: map[string]string{
					"Location":      "https://example.com",
					"X-Forwarded":   "true",
					"Cache-Control": "no-cache",
				},
			},
			want: &Operation{
				MockResponse: &MockResponse{
					Enabled: true,
					Code:    307,
					Headers: []Header{
						{Name: "Cache-Control", Value: "no-cache"},
						{Name: "Location", Value: "https://example.com"},
						{Name: "X-Forwarded", Value: "true"},
					},
				},
				IgnoreAuthentication: &Allowance{
					Enabled: true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Operation{}
			o.Fill(tt.op)

			// Compare MockResponse
			if o.MockResponse.Enabled != tt.want.MockResponse.Enabled {
				t.Errorf("MockResponse.Enabled = %v, want %v", o.MockResponse.Enabled, tt.want.MockResponse.Enabled)
			}
			if o.MockResponse.Code != tt.want.MockResponse.Code {
				t.Errorf("MockResponse.Code = %v, want %v", o.MockResponse.Code, tt.want.MockResponse.Code)
			}
			if o.MockResponse.Body != tt.want.MockResponse.Body {
				t.Errorf("MockResponse.Body = %v, want %v", o.MockResponse.Body, tt.want.MockResponse.Body)
			}

			// Compare Headers length
			if len(o.MockResponse.Headers) != len(tt.want.MockResponse.Headers) {
				t.Errorf("len(MockResponse.Headers) = %v, want %v", len(o.MockResponse.Headers), len(tt.want.MockResponse.Headers))
			}

			// Create maps for easier header comparison
			gotHeaders := make(map[string]string)
			wantHeaders := make(map[string]string)

			for _, h := range o.MockResponse.Headers {
				gotHeaders[h.Name] = h.Value
			}
			for _, h := range tt.want.MockResponse.Headers {
				wantHeaders[h.Name] = h.Value
			}

			// Compare header contents
			if !reflect.DeepEqual(gotHeaders, wantHeaders) {
				t.Errorf("MockResponse.Headers = %v, want %v", gotHeaders, wantHeaders)
			}

			// Compare IgnoreAuthentication
			if o.IgnoreAuthentication.Enabled != tt.want.IgnoreAuthentication.Enabled {
				t.Errorf("IgnoreAuthentication.Enabled = %v, want %v", o.IgnoreAuthentication.Enabled, tt.want.IgnoreAuthentication.Enabled)
			}
		})
	}
}

func TestOAS_fillMockResponsePaths(t *testing.T) {
	t.Parallel()

	// Test case 1: Basic mock response
	t.Run("basic mock response", func(t *testing.T) {
		ep := apidef.ExtendedPathsSet{
			MockResponse: []apidef.MockResponseMeta{
				{
					Path:   "/test",
					Method: "GET",
					Code:   200,
					Body:   `{"message": "success"}`,
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
				},
			},
		}

		spec := &OAS{
			T: openapi3.T{
				Paths: openapi3.Paths{},
			},
		}

		spec.fillMockResponsePaths(spec.Paths, ep)

		// Verify the mock response was correctly added to paths
		assert.Len(t, spec.Paths, 1)
		pathItem := spec.Paths["/test"]
		assert.NotNil(t, pathItem)
		assert.NotNil(t, pathItem.Get)
		assert.Equal(t, "testGET", pathItem.Get.OperationID)
		assert.Nil(t, pathItem.Post)
		assert.Nil(t, pathItem.Put)
		assert.Nil(t, pathItem.Patch)
		assert.Nil(t, pathItem.Delete)

		// Verify response
		responses := pathItem.Get.Responses
		assert.NotNil(t, responses)
		response := responses["200"]
		assert.NotNil(t, response.Value)

		// Verify content
		content := response.Value.Content
		assert.NotNil(t, content["application/json"])
		mediaType := content["application/json"]
		assert.Equal(t, `{"message": "success"}`, mediaType.Example)
		assert.Equal(t, `{"message": "success"}`, mediaType.Examples["default"].Value.Value)

		// Verify headers
		headers := response.Value.Headers
		assert.NotNil(t, headers["Content-Type"])
		assert.Equal(t, "application/json", headers["Content-Type"].Value.Schema.Value.Example)
	})

	// Test case 2: Multiple methods
	t.Run("multiple methods", func(t *testing.T) {
		ep := apidef.ExtendedPathsSet{
			MockResponse: []apidef.MockResponseMeta{
				{
					Path:   "/test",
					Method: "GET",
					Code:   200,
					Body:   `{"status": "ok"}`,
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
				},
				{
					Path:   "/test",
					Method: "POST",
					Code:   201,
					Body:   `{"id": "123"}`,
					Headers: map[string]string{
						"Content-Type": "application/json",
						"Location":     "/test/123",
					},
				},
			},
		}

		spec := &OAS{
			T: openapi3.T{
				Paths: openapi3.Paths{},
			},
		}

		spec.fillMockResponsePaths(spec.Paths, ep)

		// Verify path item
		assert.Len(t, spec.Paths, 1)
		pathItem := spec.Paths["/test"]
		assert.NotNil(t, pathItem)
		assert.NotNil(t, pathItem.Get)
		assert.NotNil(t, pathItem.Post)

		// Verify GET operation
		assert.Equal(t, "testGET", pathItem.Get.OperationID)
		getResponse := pathItem.Get.Responses["200"].Value
		assert.Equal(t, `{"status": "ok"}`, getResponse.Content["application/json"].Example)
		assert.Equal(t, "application/json", getResponse.Headers["Content-Type"].Value.Schema.Value.Example)

		// Verify POST operation
		assert.Equal(t, "testPOST", pathItem.Post.OperationID)
		postResponse := pathItem.Post.Responses["201"].Value
		assert.Equal(t, `{"id": "123"}`, postResponse.Content["application/json"].Example)
		assert.Equal(t, "application/json", postResponse.Headers["Content-Type"].Value.Schema.Value.Example)
		assert.Equal(t, "/test/123", postResponse.Headers["Location"].Value.Schema.Value.Example)
	})

	// Test case 3: No content type header
	t.Run("no content type header", func(t *testing.T) {
		ep := apidef.ExtendedPathsSet{
			MockResponse: []apidef.MockResponseMeta{
				{
					Path:   "/test",
					Method: "GET",
					Code:   204,
					Body:   "",
				},
			},
		}

		spec := &OAS{
			T: openapi3.T{
				Paths: openapi3.Paths{},
			},
		}

		spec.fillMockResponsePaths(spec.Paths, ep)

		// Verify response
		pathItem := spec.Paths["/test"]
		assert.NotNil(t, pathItem)
		response := pathItem.Get.Responses["204"].Value

		// When no content type is specified, it should default to text/plain
		assert.NotNil(t, response.Content["text/plain"])
		assert.Equal(t, "", response.Content["text/plain"].Example)
		assert.Empty(t, response.Headers)
	})
}

func compareOperations(t *testing.T, got, want *openapi3.Operation, method, path string) {
	if (got == nil) != (want == nil) {
		t.Errorf("fillMockResponsePaths() %s operation for path %s, got = %v, want = %v", method, path, got != nil, want != nil)
		return
	}

	if got == nil {
		return
	}

	if got.OperationID != want.OperationID {
		t.Errorf("fillMockResponsePaths() %s operation for path %s, got OperationID = %v, want = %v", method, path, got.OperationID, want.OperationID)
	}

	if (got.Responses == nil) != (want.Responses == nil) {
		t.Errorf("fillMockResponsePaths() %s operation for path %s, got Responses = %v, want = %v", method, path, got.Responses != nil, want.Responses != nil)
	}
}
