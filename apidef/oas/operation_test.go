package oas

import (
	"context"
	"embed"
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

func TestOAS_MockResponse_extractPathsAndOperations(t *testing.T) {
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

func TestOAS_MockResponse_fillMockResponsePaths(t *testing.T) {
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
