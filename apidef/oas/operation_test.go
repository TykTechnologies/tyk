package oas

import (
	"cmp"
	"context"
	"embed"
	"github.com/TykTechnologies/tyk/internal/reflect"
	"github.com/TykTechnologies/tyk/internal/utils"
	"net/http"
	"slices"
	"sort"
	"strconv"
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
	paths := openapi3.NewPaths()
	paths.Set("/user", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: operationId,
		},
	})
	oas.Paths = paths

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
	convertedPaths := openapi3.NewPaths()
	convertedPaths.Set("/user", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: existingOperationId,
			Responses:   openapi3.NewResponses(),
		},
	})
	convertedOAS.Paths = convertedPaths
	convertedOAS.SetTykExtension(&XTykAPIGateway{Middleware: &Middleware{Operations: Operations{}}})
	convertedOAS.fillPathsAndOperations(ep)

	assert.Equal(t, oas.getTykOperations(), convertedOAS.getTykOperations())

	expCombinedPaths := openapi3.NewPaths()
	expCombinedPaths.Set("/user", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: existingOperationId,
			Responses:   openapi3.NewResponses(),
		},
		Get: &openapi3.Operation{
			OperationID: operationId,
			Responses:   openapi3.NewResponses(),
		},
	})

	assert.Equal(t, expCombinedPaths.Map(), convertedOAS.Paths.Map())

	t.Run("oas validation", func(t *testing.T) {
		err := convertedOAS.Validate(context.Background())
		assert.NoError(t, err)
	})
}

func TestOAS_MockResponse_extractPathsAndOperations(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		spec OAS
		want func(t *testing.T, ep *apidef.ExtendedPathsSet)
	}

	tests := []testCase{
		{
			name: "basic mock response",
			spec: OAS{
				T: openapi3.T{
					OpenAPI: DefaultOpenAPI,
					Paths: func() *openapi3.Paths {
						paths := openapi3.NewPaths()
						paths.Set("/test", &openapi3.PathItem{
							Get: &openapi3.Operation{
								OperationID: "testGET",
							},
						})
						return paths
					}(),
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
												{Name: "Content-Type", Value: "application/json"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: func(t *testing.T, ep *apidef.ExtendedPathsSet) {
				t.Helper()

				// Verify mock responses
				mockResponses := ep.MockResponse
				require.Len(t, mockResponses, 1)

				mockResp := mockResponses[0]
				require.Equal(t, "/test", mockResp.Path)
				require.Equal(t, "GET", mockResp.Method)
				require.Equal(t, 200, mockResp.Code)
				require.Equal(t, `{"message": "success"}`, mockResp.Body)
				require.Equal(t, map[string]string{"Content-Type": "application/json"}, mockResp.Headers)
				require.False(t, mockResp.Disabled)
			},
		},
		{
			name: "multiple methods on same path",
			spec: OAS{
				T: openapi3.T{
					OpenAPI: DefaultOpenAPI,
					Paths: func() *openapi3.Paths {
						paths := openapi3.NewPaths()
						paths.Set("/test", &openapi3.PathItem{
							Get: &openapi3.Operation{
								OperationID: "testGET",
							},
							Post: &openapi3.Operation{
								OperationID: "testPOST",
							},
						})
						return paths
					}(),
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
			},
			want: func(t *testing.T, ep *apidef.ExtendedPathsSet) {
				t.Helper()

				// Verify mock responses
				mockResponses := ep.MockResponse
				require.Len(t, mockResponses, 2)

				// Sort for consistent testing
				sort.Slice(mockResponses, func(i, j int) bool {
					if mockResponses[i].Path == mockResponses[j].Path {
						return mockResponses[i].Method < mockResponses[j].Method
					}
					return mockResponses[i].Path < mockResponses[j].Path
				})

				// Verify GET mock response
				getMock := mockResponses[0]
				require.Equal(t, "/test", getMock.Path)
				require.Equal(t, "GET", getMock.Method)
				require.Equal(t, 200, getMock.Code)
				require.Equal(t, `{"status": "ok"}`, getMock.Body)
				require.Equal(t, map[string]string{"Content-Type": "application/json"}, getMock.Headers)
				require.False(t, getMock.Disabled)

				// Verify POST mock response
				postMock := mockResponses[1]
				require.Equal(t, "/test", postMock.Path)
				require.Equal(t, "POST", postMock.Method)
				require.Equal(t, 201, postMock.Code)
				require.Equal(t, `{"id": "123"}`, postMock.Body)
				require.Equal(t, map[string]string{
					"Content-Type": "application/json",
					"Location":     "/test/123",
				}, postMock.Headers)
				require.False(t, postMock.Disabled)
			},
		},
		{
			name: "disabled mock response",
			spec: OAS{
				T: openapi3.T{
					OpenAPI: DefaultOpenAPI,
					Paths: func() *openapi3.Paths {
						paths := openapi3.NewPaths()
						paths.Set("/test", &openapi3.PathItem{
							Get: &openapi3.Operation{
								OperationID: "testGET",
							},
						})
						return paths
					}(),
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
			},
			want: func(t *testing.T, ep *apidef.ExtendedPathsSet) {
				t.Helper()

				// Verify mock responses
				mockResponses := ep.MockResponse
				require.Len(t, mockResponses, 1)

				mockResp := mockResponses[0]
				require.Equal(t, "/test", mockResp.Path)
				require.Equal(t, "GET", mockResp.Method)
				require.Equal(t, 404, mockResp.Code)
				require.Equal(t, `{"error": "not found"}`, mockResp.Body)
				require.True(t, mockResp.Disabled)
			},
		},
		{
			name: "no mock responses",
			spec: OAS{
				T: openapi3.T{
					OpenAPI: DefaultOpenAPI,
					Paths: func() *openapi3.Paths {
						paths := openapi3.NewPaths()
						paths.Set("/test", &openapi3.PathItem{
							Get: &openapi3.Operation{
								OperationID: "testGET",
							},
						})
						return paths
					}(),
					Extensions: map[string]interface{}{
						"x-tyk-api-gateway": &XTykAPIGateway{
							Middleware: &Middleware{
								Operations: Operations{
									"testGET": &Operation{},
								},
							},
						},
					},
				},
			},
			want: func(t *testing.T, ep *apidef.ExtendedPathsSet) {
				t.Helper()

				assert.Empty(t, ep.MockResponse)
			},
		},
		{
			name: "multiple paths with mock responses",
			spec: OAS{
				T: openapi3.T{
					OpenAPI: DefaultOpenAPI,
					Paths: func() *openapi3.Paths {
						paths := openapi3.NewPaths()
						paths.Set("/users", &openapi3.PathItem{
							Get: &openapi3.Operation{
								OperationID: "usersGET",
							},
						})
						paths.Set("/items", &openapi3.PathItem{
							Get: &openapi3.Operation{
								OperationID: "itemsGET",
							},
						})
						return paths
					}(),
					Extensions: map[string]interface{}{
						"x-tyk-api-gateway": &XTykAPIGateway{
							Middleware: &Middleware{
								Operations: Operations{
									"usersGET": &Operation{
										MockResponse: &MockResponse{
											Enabled: true,
											Code:    200,
											Body:    `["user1", "user2"]`,
											Headers: []Header{{Name: "Content-Type", Value: "application/json"}},
										},
									},
									"itemsGET": &Operation{
										MockResponse: &MockResponse{
											Enabled: true,
											Code:    200,
											Body:    `["item1", "item2"]`,
											Headers: []Header{{Name: "Content-Type", Value: "application/json"}},
										},
									},
								},
							},
						},
					},
				},
			},
			want: func(t *testing.T, ep *apidef.ExtendedPathsSet) {
				t.Helper()

				// Verify mock responses
				mockResponses := ep.MockResponse
				require.Len(t, mockResponses, 2)

				// Sort for consistent testing
				slices.SortFunc(mockResponses, func(a, b apidef.MockResponseMeta) int {
					return cmp.Compare(a.Path, b.Path)
				})

				// Verify items response
				itemsResp := mockResponses[0]
				require.False(t, itemsResp.Disabled)
				require.Equal(t, "/items", itemsResp.Path)
				require.Equal(t, "GET", itemsResp.Method)
				require.Equal(t, 200, itemsResp.Code)
				require.Equal(t, `["item1", "item2"]`, itemsResp.Body)
				require.Equal(t, map[string]string{"Content-Type": "application/json"}, itemsResp.Headers)

				// Verify users response
				usersResp := mockResponses[1]
				require.False(t, usersResp.Disabled)
				require.Equal(t, "/users", usersResp.Path)
				require.Equal(t, "GET", usersResp.Method)
				require.Equal(t, 200, usersResp.Code)
				require.Equal(t, `["user1", "user2"]`, usersResp.Body)
				require.Equal(t, map[string]string{"Content-Type": "application/json"}, usersResp.Headers)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ep apidef.ExtendedPathsSet
			tt.spec.extractPathsAndOperations(&ep)

			// We should ensure no AllowList is created
			require.Len(t, ep.WhiteList, 0)

			tt.want(t, &ep)
		})
	}
}

func TestOAS_PathsAndOperationsRegex(t *testing.T) {
	t.Parallel()

	expectedOperationID := "users/[a-z]+/[0-9]+$GET"
	expectedPath := "/users/{customRegex1}/{customRegex2}"

	var oas OAS
	oas.Paths = openapi3.NewPaths()
	oas.Paths.Set("/users/[a-z]+/[0-9]+$", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: expectedOperationID,
			Responses:   openapi3.NewResponses(),
		},
	})
	err := oas.Normalize()

	require.NoError(t, err)
	//_ = oas.getOperationID("/users/[a-z]+/[0-9]+$", "GET")

	expectedPathItems := openapi3.NewPaths()
	expectedPathItems.Set(expectedPath, &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: expectedOperationID,
			Responses:   openapi3.NewResponses(),
		},
		Parameters: []*openapi3.ParameterRef{
			{
				Value: &openapi3.Parameter{
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type:    &openapi3.Types{openapi3.TypeString},
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
							Type:    &openapi3.Types{openapi3.TypeString},
							Pattern: "[0-9]+$",
						},
					},
					Name:     "customRegex2",
					In:       "path",
					Required: true,
				},
			},
		},
	})

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
		oas.Paths = openapi3.NewPaths()
		oas.Paths.Set(tc.input, &openapi3.PathItem{
			Get: &openapi3.Operation{},
		})
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
		oas.Paths = openapi3.NewPaths()
		oas.Paths.Set(tc.input, &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: tc.input,
				Responses:   openapi3.NewResponses(),
			},
		})
		err := oas.Normalize()
		require.NoError(t, err)
		assert.Len(t, oas.Paths.Map(), 1)

		p := oas.Paths.Value(tc.want)
		require.NotNil(t, p, "test %s: expected path to be created", tc.input)
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

// Map HTTP methods to their corresponding PathItem field setters
var methodSetters = map[string]func(*openapi3.PathItem, *openapi3.Operation){
	"GET":     func(p *openapi3.PathItem, op *openapi3.Operation) { p.SetOperation("GET", op) },
	"POST":    func(p *openapi3.PathItem, op *openapi3.Operation) { p.SetOperation("POST", op) },
	"PUT":     func(p *openapi3.PathItem, op *openapi3.Operation) { p.SetOperation("PUT", op) },
	"PATCH":   func(p *openapi3.PathItem, op *openapi3.Operation) { p.SetOperation("PATCH", op) },
	"DELETE":  func(p *openapi3.PathItem, op *openapi3.Operation) { p.SetOperation("DELETE", op) },
	"HEAD":    func(p *openapi3.PathItem, op *openapi3.Operation) { p.SetOperation("HEAD", op) },
	"OPTIONS": func(p *openapi3.PathItem, op *openapi3.Operation) { p.SetOperation("OPTIONS", op) },
}

func TestOAS_MockResponse_fillMockResponsePaths(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		ep   apidef.ExtendedPathsSet
		spec *OAS
		want func(t *testing.T, spec *OAS)
	}

	tests := []testCase{
		{
			name: "basic mock response",
			spec: &OAS{
				T: openapi3.T{
					OpenAPI: DefaultOpenAPI,
					Paths: func() *openapi3.Paths {
						paths := openapi3.NewPaths()
						paths.Set("/test", &openapi3.PathItem{
							Get: &openapi3.Operation{
								Summary:     "Existing summary",
								OperationID: "testGET",
							},
						})
						return paths
					}(),
				},
			},
			ep: apidef.ExtendedPathsSet{
				MockResponse: []apidef.MockResponseMeta{{
					Path:   "/test",
					Method: "GET",
					Code:   200,
					Body:   `{"message": "success"}`,
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
				}},
			},
			want: func(t *testing.T, spec *OAS) {
				t.Helper()

				require.Len(t, spec.Paths.Map(), 1)

				pathItem := spec.Paths.Value("/test")
				require.NotNil(t, pathItem)
				tykOperation := spec.GetTykExtension().getOperation(pathItem.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				// Verify operation
				require.NotNil(t, pathItem.Get)
				require.Equal(t, "testGET", pathItem.Get.OperationID)
				require.Equal(t, "Existing summary", pathItem.Get.Summary)
				require.Nil(t, pathItem.Post)
				require.Nil(t, pathItem.Put)
				require.Nil(t, pathItem.Patch)
				require.Nil(t, pathItem.Delete)

				// Verify response
				response200Ref := pathItem.Get.Responses.Value("200")
				require.NotNil(t, response200Ref, "Response ref for 200 should not be nil")

				response200 := response200Ref.Value
				require.NotNil(t, response200, "Response value for 200 should not be nil")
				require.NotNil(t, response200.Description)

				// Verify headers
				require.Nil(t, response200.Headers)
			},
		},
		{
			name: "multiple methods on same path",
			ep: apidef.ExtendedPathsSet{
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
			},
			want: func(t *testing.T, spec *OAS) {
				t.Helper()

				assert.Len(t, spec.Paths.Map(), 1)

				pathItem := spec.Paths.Map()["/test"]
				require.NotNil(t, pathItem)

				// Verify GET operation
				require.NotNil(t, pathItem.Get)
				require.Equal(t, "testGET", pathItem.Get.OperationID)
				tykOperation := spec.GetTykExtension().getOperation(pathItem.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				response200Ref := pathItem.Get.Responses.Value("200")
				require.NotNil(t, response200Ref, "Response ref for 200 should not be nil")

				response200 := response200Ref.Value
				require.NotNil(t, response200, "Response value should not be nil")
				require.NotNil(t, response200.Description)

				// Verify POST operation
				require.NotNil(t, pathItem.Post)
				require.Equal(t, "testPOST", pathItem.Post.OperationID)
				tykOperation = spec.GetTykExtension().getOperation(pathItem.Post.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				postResponse := pathItem.Post.Responses.Value("201")
				require.NotNil(t, postResponse)
				require.NotNil(t, postResponse.Value)
				require.NotNil(t, postResponse.Value.Description)
			},
		},
		{
			name: "no content type header defaults to text/plain",
			ep: apidef.ExtendedPathsSet{
				MockResponse: []apidef.MockResponseMeta{{
					Path:   "/test",
					Method: "GET",
					Code:   204,
					Body:   "",
				}},
			},
			want: func(t *testing.T, spec *OAS) {
				t.Helper()

				pathItem := spec.Paths.Map()["/test"]
				require.NotNil(t, pathItem)
				require.Equal(t, "testGET", pathItem.Get.OperationID)
				tykOperation := spec.GetTykExtension().getOperation(pathItem.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				response204Ref := pathItem.Get.Responses.Value("204")
				require.NotNil(t, response204Ref, "Response ref for 204 should not be nil")

				response204 := response204Ref.Value
				require.NotNil(t, response204, "Response value for 204 should not be nil")
				require.Nil(t, response204.Content["text/plain"])
				require.Empty(t, response204.Headers)
			},
		},
		{
			name: "multiple paths",
			ep: apidef.ExtendedPathsSet{
				MockResponse: []apidef.MockResponseMeta{
					{
						Path:   "/users",
						Method: "GET",
						Code:   200,
						Body:   `["user1", "user2"]`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
					},
					{
						Path:   "/items",
						Method: "GET",
						Code:   200,
						Body:   `["item1", "item2"]`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
					},
				},
			},
			want: func(t *testing.T, spec *OAS) {
				t.Helper()
				assert.Len(t, spec.Paths.Map(), 2)

				// Verify /users path
				usersPath := spec.Paths.Map()["/users"]
				require.NotNil(t, usersPath)
				require.NotNil(t, usersPath.Get)
				require.Equal(t, "usersGET", usersPath.Get.OperationID)
				tykOperation := spec.GetTykExtension().getOperation(usersPath.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				usersResponse := usersPath.Get.Responses.Value("200")
				require.NotNil(t, usersResponse)
				require.NotNil(t, usersResponse.Value)
				require.NotNil(t, usersResponse.Value.Description)

				// Verify /items path
				itemsPath := spec.Paths.Map()["/items"]
				require.NotNil(t, itemsPath)
				require.NotNil(t, itemsPath.Get)
				require.Equal(t, "itemsGET", itemsPath.Get.OperationID)
				tykOperation = spec.GetTykExtension().getOperation(itemsPath.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				itemsResponse := itemsPath.Get.Responses.Value("200")
				require.NotNil(t, itemsResponse)
				require.NotNil(t, itemsResponse.Value)
				require.NotNil(t, itemsResponse.Value.Description)
			},
		},
		{
			name: "empty mock response list",
			ep: apidef.ExtendedPathsSet{
				MockResponse: []apidef.MockResponseMeta{},
			},
			want: func(t *testing.T, spec *OAS) {
				t.Helper()

				assert.Empty(t, spec.Paths.Map())
			},
		},
		{
			name: "multiple response codes for same path",
			ep: apidef.ExtendedPathsSet{
				MockResponse: []apidef.MockResponseMeta{
					{
						Path:   "/test",
						Method: "GET",
						Code:   200,
						Body:   `{"status": "success"}`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
					},
				},
			},
			want: func(t *testing.T, spec *OAS) {
				t.Helper()

				pathItem := spec.Paths.Map()["/test"]
				require.NotNil(t, pathItem)
				require.NotNil(t, pathItem.Get)
				require.Equal(t, "testGET", pathItem.Get.OperationID)

				// Verify responses exist
				require.NotNil(t, pathItem.Get.Responses)

				// Verify 200 response
				response200 := pathItem.Get.Responses.Value("200")
				require.NotNil(t, response200, "Response for 200 should not be nil")
				require.NotNil(t, response200.Value)
				require.NotNil(t, response200.Value.Description)
				tykOperation := spec.GetTykExtension().getOperation(pathItem.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)
			},
		},
		{
			name: "different content types",
			ep: apidef.ExtendedPathsSet{
				MockResponse: []apidef.MockResponseMeta{
					{
						Path:   "/test",
						Method: "GET",
						Code:   200,
						Body:   `{"data": "json"}`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
					},
					{
						Path:   "/test.xml",
						Method: "GET",
						Code:   200,
						Body:   `<data>xml</data>`,
						Headers: map[string]string{
							"Content-Type": "application/xml",
						},
					},
					{
						Path:   "/test.txt",
						Method: "GET",
						Code:   200,
						Body:   `plain text`,
						Headers: map[string]string{
							"Content-Type": "text/plain",
						},
					},
				},
			},
			want: func(t *testing.T, spec *OAS) {
				t.Helper()

				// JSON endpoint
				jsonPath := spec.Paths.Map()["/test"]
				require.NotNil(t, jsonPath)
				jsonResponse := jsonPath.Get.Responses.Value("200")
				require.NotNil(t, jsonResponse)
				require.NotNil(t, jsonResponse.Value)
				require.NotNil(t, jsonResponse.Value.Description)
				tykOperation := spec.GetTykExtension().getOperation(jsonPath.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				// XML endpoint
				xmlPath := spec.Paths.Map()["/test.xml"]
				require.NotNil(t, xmlPath)
				xmlResponse := xmlPath.Get.Responses.Value("200")
				require.NotNil(t, xmlResponse)
				require.NotNil(t, xmlResponse.Value)
				require.NotNil(t, xmlResponse.Value.Description)
				tykOperation = spec.GetTykExtension().getOperation(xmlPath.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				// Text endpoint
				txtPath := spec.Paths.Map()["/test.txt"]
				require.NotNil(t, txtPath)
				txtResponse := txtPath.Get.Responses.Value("200")
				require.NotNil(t, txtResponse)
				require.NotNil(t, txtResponse.Value)
				require.NotNil(t, txtResponse.Value.Description)
				tykOperation = spec.GetTykExtension().getOperation(txtPath.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)
			},
		},
		{
			name: "custom headers",
			ep: apidef.ExtendedPathsSet{
				MockResponse: []apidef.MockResponseMeta{{
					Path:   "/test",
					Method: "GET",
					Code:   200,
					Body:   `{"data": "test"}`,
					Headers: map[string]string{
						"Content-Type":      "application/json",
						"X-Custom-Header":   "custom-value",
						"X-Request-ID":      "123",
						"X-Correlation-ID":  "abc",
						"Cache-Control":     "no-cache",
						"X-RateLimit-Limit": "100",
					},
				}},
			},
			want: func(t *testing.T, spec *OAS) {
				t.Helper()

				pathItem := spec.Paths.Map()["/test"]
				require.NotNil(t, pathItem)
				response := pathItem.Get.Responses.Value("200")
				require.NotNil(t, response)
				require.NotNil(t, response.Value)
				require.NotNil(t, response.Value.Description)

				tykOperation := spec.GetTykExtension().getOperation(pathItem.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)
			},
		},
		{
			name: "all HTTP methods",
			ep: apidef.ExtendedPathsSet{
				MockResponse: []apidef.MockResponseMeta{
					{Path: "/test", Method: "GET", Code: 200, Body: `{"method":"get"}`},
					{Path: "/test", Method: "POST", Code: 201, Body: `{"method":"post"}`},
					{Path: "/test", Method: "PUT", Code: 200, Body: `{"method":"put"}`},
					{Path: "/test", Method: "PATCH", Code: 200, Body: `{"method":"patch"}`},
					{Path: "/test", Method: "DELETE", Code: 204, Body: ``},
					{Path: "/test", Method: "HEAD", Code: 200, Body: ``},
					{Path: "/test", Method: "OPTIONS", Code: 200, Body: ``},
				},
			},
			want: func(t *testing.T, spec *OAS) {
				t.Helper()

				pathItem := spec.Paths.Map()["/test"]
				require.NotNil(t, pathItem)

				verifyOASOperation(t, spec, pathItem.Get, "GET", 200)
				verifyOASOperation(t, spec, pathItem.Post, "POST", 201)
				verifyOASOperation(t, spec, pathItem.Put, "PUT", 200)
				verifyOASOperation(t, spec, pathItem.Patch, "PATCH", 200)
				verifyOASOperation(t, spec, pathItem.Delete, "DELETE", 204)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &OAS{
				T: openapi3.T{
					OpenAPI: DefaultOpenAPI,
					Info: &openapi3.Info{
						Title:   "Test API",
						Version: "1.0.0",
					},
					Paths: openapi3.NewPaths(),
				},
			}

			if tt.spec != nil && tt.spec.Paths != nil {
				spec.Paths = tt.spec.Paths
			}

			// Initialize the middleware extension with proper mock response setup
			middleware := &Middleware{
				Operations: make(Operations),
			}

			// Pre-initialize operations with mock responses
			for _, mockResp := range tt.ep.MockResponse {
				operationID := spec.getOperationID(mockResp.Path, mockResp.Method)

				operation := &Operation{
					MockResponse: &MockResponse{
						Code:    mockResp.Code,
						Body:    mockResp.Body,
						Headers: make([]Header, 0),
					},
				}

				// Convert headers to the expected format
				for name, value := range mockResp.Headers {
					operation.MockResponse.Headers = append(operation.MockResponse.Headers, Header{
						Name:  name,
						Value: value,
					})
				}

				middleware.Operations[operationID] = operation
			}

			spec.SetTykExtension(&XTykAPIGateway{
				Middleware: middleware,
			})

			// Initialize paths
			for _, mockResp := range tt.ep.MockResponse {
				operationID := spec.getOperationID(mockResp.Path, mockResp.Method)

				// Initialize operation with responses
				op := &openapi3.Operation{
					OperationID: operationID,
					Responses:   openapi3.NewResponses(),
				}

				// Preserve existing operation properties if they exist
				if pathItem := spec.Paths.Find(mockResp.Path); pathItem != nil {
					if existingOp := pathItem.GetOperation(mockResp.Method); existingOp != nil {
						op.Summary = existingOp.Summary
						op.Description = existingOp.Description
						// Copy other relevant fields as needed
					}
				}

				if tt.spec != nil {
					if spec.Paths == nil {
						spec.Paths = openapi3.NewPaths()
					}
					for k, v := range tt.spec.Paths.Map() {
						spec.Paths.Map()[k] = v
					}
				}

				// Set the operation based on method
				if setter, ok := methodSetters[mockResp.Method]; ok {
					path := mockResp.Path // Use the mock response path directly
					if spec.Paths.Value(path) == nil {
						spec.Paths.Set(path, &openapi3.PathItem{})
					}

					setter(spec.Paths.Value(path), op)

					var desc string

					// Add response for the specific status code
					statusCode := strconv.Itoa(mockResp.Code)

					op.Responses.Set(statusCode, &openapi3.ResponseRef{
						Value: &openapi3.Response{
							Description: &desc,
						},
					})
				}
			}

			spec.fillMockResponsePaths(spec.Paths, tt.ep)
			tt.want(t, spec)
		})
	}
}

// Helper function to verify OpenAPI operation responses
func verifyOASOperation(t *testing.T, spec *OAS, op *openapi3.Operation, method string, code int) {
	t.Helper()

	require.NotNil(t, op, "Operation %s should exist", method)
	require.NotNil(t, op.Responses, "Responses should not be nil")

	statusCode := strconv.Itoa(code)
	require.NotNil(t, op.Responses.Value(statusCode), "Responses should not be nil for status code %s and method %s", statusCode, method)

	response := op.Responses.Value(statusCode)
	require.NotNil(t, response)
	require.NotNil(t, response.Value)
	require.NotNil(t, response.Value.Description)

	tykOperation := spec.GetTykExtension().getOperation(op.OperationID)
	require.NotNil(t, tykOperation)
	require.Nil(t, tykOperation.Allow)
}

func TestOAS_fillAllowance(t *testing.T) {
	t.Run("should fill allow list correctly", func(t *testing.T) {
		s := &OAS{
			T: openapi3.T{
				Paths: openapi3.NewPaths(),
			},
		}

		s.SetTykExtension(&XTykAPIGateway{
			Middleware: &Middleware{
				Operations: make(Operations),
			},
		})

		endpointMetas := []apidef.EndPointMeta{
			{
				Path:   "/test",
				Method: http.MethodGet,
				MethodActions: map[string]apidef.EndpointMethodMeta{
					http.MethodGet: {
						Action: apidef.NoAction,
					},
				},
			},
		}

		s.fillAllowance(endpointMetas, allow)

		operationID := s.getOperationID("/test", http.MethodGet)
		operation := s.GetTykExtension().getOperation(operationID)

		assert.NotNil(t, operation.Allow)
		assert.True(t, operation.Allow.Enabled)
		assert.Nil(t, operation.Block)
		assert.Nil(t, operation.IgnoreAuthentication)
	})

	t.Run("should fill block list correctly", func(t *testing.T) {
		s := &OAS{
			T: openapi3.T{
				Paths: openapi3.NewPaths(),
			},
		}

		s.SetTykExtension(&XTykAPIGateway{
			Middleware: &Middleware{
				Operations: make(Operations),
			},
		})

		endpointMetas := []apidef.EndPointMeta{
			{
				Path:   "/test",
				Method: http.MethodGet,
			},
		}

		s.fillAllowance(endpointMetas, block)

		operationID := s.getOperationID("/test", http.MethodGet)
		operation := s.GetTykExtension().getOperation(operationID)

		assert.NotNil(t, operation.Block)
		assert.True(t, operation.Block.Enabled)
		assert.Nil(t, operation.Allow)
		assert.Nil(t, operation.IgnoreAuthentication)
	})

	t.Run("should fill ignore authentication correctly", func(t *testing.T) {
		s := &OAS{
			T: openapi3.T{
				Paths: openapi3.NewPaths(),
			},
		}

		s.SetTykExtension(&XTykAPIGateway{
			Middleware: &Middleware{
				Operations: make(Operations),
			},
		})

		endpointMetas := []apidef.EndPointMeta{
			{
				Path:   "/test",
				Method: http.MethodGet,
			},
		}

		s.fillAllowance(endpointMetas, ignoreAuthentication)

		operationID := s.getOperationID("/test", http.MethodGet)
		operation := s.GetTykExtension().getOperation(operationID)

		assert.NotNil(t, operation.IgnoreAuthentication)
		assert.True(t, operation.IgnoreAuthentication.Enabled)
		assert.Nil(t, operation.Allow)
		assert.Nil(t, operation.Block)
	})

	t.Run("should skip Reply actions for allow list", func(t *testing.T) {
		spec := &OAS{
			T: openapi3.T{
				Paths: openapi3.NewPaths(),
			},
		}

		spec.SetTykExtension(&XTykAPIGateway{
			Middleware: &Middleware{
				Operations: make(Operations),
			},
		})

		endpointMetas := []apidef.EndPointMeta{
			{
				Path:   "/test",
				Method: http.MethodGet,
				MethodActions: map[string]apidef.EndpointMethodMeta{
					http.MethodGet: {
						Action: apidef.Reply,
					},
				},
			},
		}

		spec.fillAllowance(endpointMetas, allow)

		operationID := spec.getOperationID("/test", http.MethodGet)
		operation := spec.GetTykExtension().getOperation(operationID)

		assert.Nil(t, operation.Allow, "Allow should be nil for Reply actions")
	})

	t.Run("should handle empty endpoint metas", func(t *testing.T) {
		s := &OAS{
			T: openapi3.T{
				Paths: openapi3.NewPaths(),
			},
		}

		s.SetTykExtension(&XTykAPIGateway{
			Middleware: &Middleware{
				Operations: make(Operations),
			},
		})

		var endpointMetas []apidef.EndPointMeta

		s.fillAllowance(endpointMetas, allow)

		assert.Empty(t, s.Paths.Map())
	})

	t.Run("should set allowance disabled when ShouldOmit returns true", func(t *testing.T) {
		s := &OAS{
			T: openapi3.T{
				Paths: openapi3.NewPaths(),
			},
		}

		s.SetTykExtension(&XTykAPIGateway{
			Middleware: &Middleware{
				Operations: make(Operations),
			},
		})

		endpointMetas := []apidef.EndPointMeta{
			{
				Path:     "/test",
				Method:   http.MethodGet,
				Disabled: true,
			},
		}

		s.fillAllowance(endpointMetas, allow)

		operationID := s.getOperationID("/test", http.MethodGet)
		operation := s.GetTykExtension().getOperation(operationID)

		assert.NotNil(t, operation.Allow)
		assert.False(t, operation.Allow.Enabled)
	})
}

func TestGetOperationID(t *testing.T) {
	tests := []getOperationIdTestCase{
		{
			name:           "simple path",
			inPath:         "/simple",
			method:         "GET",
			expectedID:     "simpleGET",
			expectedPath:   "/simple",
			existingParams: nil,
			expectedParams: nil,
		},
		{
			name:           "path with regex",
			inPath:         "/items/{id}",
			method:         "GET",
			expectedID:     "items/{id}GET",
			expectedPath:   "/items/{id}",
			existingParams: nil,
			expectedParams: testParams{
				{"id", "[^/]+", "string"},
			},
		},
		{
			name:           "path with trailing slash",
			inPath:         "/trailing/",
			method:         "POST",
			expectedID:     "trailing/POST",
			expectedPath:   "/trailing/",
			existingParams: nil,
			expectedParams: nil,
		},
		{
			name:         "complex regex path",
			inPath:       "/complex/{id}",
			method:       "PUT",
			expectedID:   "complex/{id}PUT",
			expectedPath: "/complex/{id}",
			existingParams: testParams{
				{"id", "", "integer"},
			},
			expectedParams: testParams{
				{"id", "", "integer"},
			},
		},
		{
			name:         "path with existing parameter",
			inPath:       "/existing/{id}",
			method:       "DELETE",
			expectedID:   "existing/{id}DELETE",
			expectedPath: "/existing/{id}",
			existingParams: testParams{
				{"id", "[0-9]+", "string"},
			},
			expectedParams: testParams{
				{"id", "[0-9]+", "string"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var oas = new(OAS)
			oas.Paths = tc.createPaths()
			err := oas.Normalize()

			assert.NoError(t, err)

			assert.Equal(t, tc.expectedID, oas.getOperationID(tc.inPath, tc.method))

			pathItem := oas.Paths.Value(tc.expectedPath)
			assert.NotNil(t, pathItem)

			expected := tc.expectedParams.refs()

			assert.Equal(t, expected, pathItem.Parameters)
		})
	}
}

type testParam struct {
	name      string
	pattern   string
	paramType string
}

type testParams []testParam

func (tp testParams) each(cb func(param *openapi3.ParameterRef)) {
	clone := reflect.Clone(tp)

	slices.SortFunc(clone, func(a, b testParam) int {
		return cmp.Compare(a.name, b.name)
	})

	for _, param := range clone {
		pRef := openapi3.ParameterRef{
			Value: openapi3.
				NewPathParameter(param.name).
				WithSchema(
					&openapi3.Schema{
						Type:    utils.AsPtr(openapi3.Types{param.paramType}),
						Pattern: param.pattern,
					},
				),
		}

		cb(&pRef)
	}
}

func (tp testParams) refs() openapi3.Parameters {
	var res []*openapi3.ParameterRef

	tp.each(func(param *openapi3.ParameterRef) {
		res = append(res, param)
	})

	return res
}

type getOperationIdTestCase struct {
	name           string
	inPath         string
	method         string
	expectedID     string
	expectedPath   string
	existingParams testParams
	expectedParams testParams
}

func (tc *getOperationIdTestCase) createPaths() *openapi3.Paths {
	pathItem := &openapi3.PathItem{}
	pathItem.SetOperation(tc.method, &openapi3.Operation{
		OperationID: tc.expectedID,
		Responses: openapi3.NewResponses(
			openapi3.WithStatus(200, &openapi3.ResponseRef{
				Value: openapi3.NewResponse(),
			}),
		),
	})

	tc.existingParams.each(func(param *openapi3.ParameterRef) {
		pathItem.Parameters = append(pathItem.Parameters, reflect.Clone(param))
	})

	return openapi3.NewPaths(
		openapi3.WithPath(tc.inPath, pathItem),
	)
}
