package oas

import (
	"context"
	"embed"
	"net/http"
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
	convertedOAS.Paths = paths
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

	assert.Equal(t, expCombinedPaths, convertedOAS.Paths)

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
				require.Len(t, mockResponses, 0)
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
				require.Len(t, mockResponses, 0)
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
				require.Len(t, mockResponses, 0)
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
				require.Len(t, mockResponses, 0)
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

	_ = oas.getOperationID("/users/[a-z]+/[0-9]+$", "GET")

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
			Get: &openapi3.Operation{},
		})
		// got := oas.getOperationID(tc.input, "GET")

		pathKeys := make([]string, 0, len(oas.Paths.Map()))
		for k := range oas.Paths.Map() {
			pathKeys = append(pathKeys, k)
		}

		assert.Lenf(t, oas.Paths, 1, "Expected one path key being created, got %#v", pathKeys)
		_, ok := oas.Paths.Map()[tc.want]
		assert.True(t, ok)

		p, ok := oas.Paths.Map()[tc.want]
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

// Map HTTP methods to their corresponding PathItem field setters
var methodSetters = map[string]func(*openapi3.PathItem, *openapi3.Operation){
	"GET":     func(p *openapi3.PathItem, op *openapi3.Operation) { p.Get = op },
	"POST":    func(p *openapi3.PathItem, op *openapi3.Operation) { p.Post = op },
	"PUT":     func(p *openapi3.PathItem, op *openapi3.Operation) { p.Put = op },
	"PATCH":   func(p *openapi3.PathItem, op *openapi3.Operation) { p.Patch = op },
	"DELETE":  func(p *openapi3.PathItem, op *openapi3.Operation) { p.Delete = op },
	"HEAD":    func(p *openapi3.PathItem, op *openapi3.Operation) { p.Head = op },
	"OPTIONS": func(p *openapi3.PathItem, op *openapi3.Operation) { p.Options = op },
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

				require.Len(t, spec.Paths, 1)

				pathItem := spec.Paths.Map()["/test"]
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
				response200Ref := pathItem.Get.Responses.Map()["200"]
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

				assert.Len(t, spec.Paths, 1)

				pathItem := spec.Paths.Map()["/test"]
				require.NotNil(t, pathItem)

				// Verify GET operation
				require.NotNil(t, pathItem.Get)
				require.Equal(t, "testGET", pathItem.Get.OperationID)
				tykOperation := spec.GetTykExtension().getOperation(pathItem.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				response200Ref := pathItem.Get.Responses.Map()["200"]
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

				postResponse := pathItem.Post.Responses.Map()["201"].Value
				require.NotNil(t, postResponse)
				require.NotNil(t, postResponse.Description)
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

				response204Ref := pathItem.Get.Responses.Map()["204"]
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
				assert.Len(t, spec.Paths, 2)

				// Verify /users path
				usersPath := spec.Paths.Map()["/users"]
				require.NotNil(t, usersPath)
				require.NotNil(t, usersPath.Get)
				require.Equal(t, "usersGET", usersPath.Get.OperationID)
				tykOperation := spec.GetTykExtension().getOperation(usersPath.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				usersResponse := usersPath.Get.Responses.Map()["200"].Value
				require.NotNil(t, usersResponse)
				require.NotNil(t, usersResponse.Description)

				// Verify /items path
				itemsPath := spec.Paths.Map()["/items"]
				require.NotNil(t, itemsPath)
				require.NotNil(t, itemsPath.Get)
				require.Equal(t, "itemsGET", itemsPath.Get.OperationID)
				tykOperation = spec.GetTykExtension().getOperation(itemsPath.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				itemsResponse := itemsPath.Get.Responses.Map()["200"].Value
				require.NotNil(t, itemsResponse)
				require.NotNil(t, itemsResponse.Description)
			},
		},
		{
			name: "empty mock response list",
			ep: apidef.ExtendedPathsSet{
				MockResponse: []apidef.MockResponseMeta{},
			},
			want: func(t *testing.T, spec *OAS) {
				t.Helper()

				assert.Empty(t, spec.Paths)
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
				response200 := pathItem.Get.Responses.Map()["200"]
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
				jsonResponse := jsonPath.Get.Responses.Map()["200"].Value
				require.NotNil(t, jsonResponse)
				require.NotNil(t, jsonResponse.Description)
				tykOperation := spec.GetTykExtension().getOperation(jsonPath.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				// XML endpoint
				xmlPath := spec.Paths.Map()["/test.xml"]
				require.NotNil(t, xmlPath)
				xmlResponse := xmlPath.Get.Responses.Map()["200"].Value
				require.NotNil(t, xmlResponse)
				require.NotNil(t, xmlResponse.Description)
				tykOperation = spec.GetTykExtension().getOperation(xmlPath.Get.OperationID)
				require.NotNil(t, tykOperation)
				require.Nil(t, tykOperation.Allow)

				// Text endpoint
				txtPath := spec.Paths.Map()["/test.txt"]
				require.NotNil(t, txtPath)
				txtResponse := txtPath.Get.Responses.Map()["200"].Value
				require.NotNil(t, txtResponse)
				require.NotNil(t, txtResponse.Description)
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
				response := pathItem.Get.Responses.Map()["200"].Value
				require.NotNil(t, response)
				require.NotNil(t, response.Description)

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
					if spec.Paths.Map()[path] == nil {
						spec.Paths.Map()[path] = &openapi3.PathItem{}
					}
					setter(spec.Paths.Map()[path], op)

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

			spec.fillMockResponsePaths(*spec.Paths, tt.ep)
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
	require.NotNil(t, op.Responses.Map()[statusCode], "Responses should not be nil for status code %s and method %s", statusCode, method)

	response := op.Responses.Map()[statusCode].Value
	require.NotNil(t, response)
	require.NotNil(t, response.Description)

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

		assert.Empty(t, s.Paths)
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

func TestSplitPath(t *testing.T) {
	tests := map[string]struct {
		input     string
		wantParts []pathPart
		wantRegex bool
	}{
		"simple path": {
			input: "/test/path",
			wantParts: []pathPart{
				{name: "test", value: "test", isRegex: false},
				{name: "path", value: "path", isRegex: false},
			},
			wantRegex: false,
		},
		"path with regex": {
			input: "/test/.*/end",
			wantParts: []pathPart{
				{name: "test", value: "test", isRegex: false},
				{name: "customRegex1", value: ".*", isRegex: true},
				{name: "end", value: "end", isRegex: false},
			},
			wantRegex: true,
		},
		"path with curly braces": {
			input: "/users/{id}/profile",
			wantParts: []pathPart{
				{name: "users", value: "users", isRegex: false},
				{name: "id", isRegex: true},
				{name: "profile", value: "profile", isRegex: false},
			},
			wantRegex: true,
		},
		"path with named regex": {
			input: "/users/{userId:[0-9]+}/posts",
			wantParts: []pathPart{
				{name: "users", value: "users", isRegex: false},
				{name: "userId", isRegex: true},
				{name: "posts", value: "posts", isRegex: false},
			},
			wantRegex: true,
		},
		"path with named direct regex": {
			input: "/users/[0-9]+/posts",
			wantParts: []pathPart{
				{name: "users", value: "users", isRegex: false},
				{name: "customRegex1", value: "[0-9]+", isRegex: true},
				{name: "posts", value: "posts", isRegex: false},
			},
			wantRegex: true,
		},
		"empty path": {
			input:     "",
			wantParts: []pathPart{},
			wantRegex: false,
		},
		"root path": {
			input:     "/",
			wantParts: []pathPart{},
			wantRegex: false,
		},
		"path with multiple regexes": {
			input: "/users/{userId:[0-9]+}/posts/{postId:[a-z]+}/[a-z]+/{[0-9]{2}}/[a-z]{10}/abc/{id}/def/[0-9]+",
			wantParts: []pathPart{
				{name: "users", value: "users", isRegex: false},
				{name: "userId", isRegex: true},
				{name: "posts", value: "posts", isRegex: false},
				{name: "postId", isRegex: true},
				{name: "customRegex1", value: "[a-z]+", isRegex: true},
				{name: "customRegex2", isRegex: true},
				{name: "customRegex3", value: "[a-z]{10}", isRegex: true},
				{name: "abc", value: "abc", isRegex: false},
				{name: "id", isRegex: true},
				{name: "def", value: "def", isRegex: false},
				{name: "customRegex4", value: "[0-9]+", isRegex: true},
			},
			wantRegex: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotParts, gotRegex := splitPath(tc.input)

			assert.Equal(t, tc.wantRegex, gotRegex, "regex detection mismatch")
			assert.Equal(t, tc.wantParts, gotParts, "parts mismatch")
		})
	}
}

func TestGetOperationID(t *testing.T) {
	type expectedParam struct {
		pattern   string
		paramType string
	}

	tests := map[string]struct {
		inPath         string
		method         string
		expectedID     string
		expectedPath   string
		existingParams map[string]expectedParam
		expectedParams map[string]expectedParam
	}{
		"simple path": {
			inPath:         "/simple",
			method:         "GET",
			expectedID:     "simpleGET",
			expectedPath:   "/simple",
			existingParams: nil,
			expectedParams: nil,
		},
		"path with regex": {
			inPath:         "/items/{id}",
			method:         "GET",
			expectedID:     "items/{id}GET",
			expectedPath:   "/items/{id}",
			existingParams: nil,
			expectedParams: map[string]expectedParam{
				"id": {pattern: "", paramType: "string"},
			},
		},
		"path with trailing slash": {
			inPath:         "/trailing/",
			method:         "POST",
			expectedID:     "trailing/POST",
			expectedPath:   "/trailing/",
			existingParams: nil,
			expectedParams: nil,
		},
		"complex regex path": {
			inPath:       "/complex/{id}",
			method:       "PUT",
			expectedID:   "complex/{id}PUT",
			expectedPath: "/complex/{id}",
			existingParams: map[string]expectedParam{
				"id": {pattern: "", paramType: "integer"},
			},
			expectedParams: map[string]expectedParam{
				"id": {pattern: "", paramType: "integer"},
			},
		},
		"path with existing parameter": {
			inPath:       "/existing/{id}",
			method:       "DELETE",
			expectedID:   "existing/{id}DELETE",
			expectedPath: "/existing/{id}",
			existingParams: map[string]expectedParam{
				"id": {pattern: "[0-9]+", paramType: "string"},
			},
			expectedParams: map[string]expectedParam{
				"id": {pattern: "[0-9]+", paramType: "string"},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			oas := &OAS{
				T: openapi3.T{
					Paths: openapi3.NewPaths(),
				},
			}

			// Prepopulate existing parameters if any
			if tc.existingParams != nil {
				pathItem := &openapi3.PathItem{}
				for paramName, param := range tc.existingParams {
					pathItem.Parameters = append(pathItem.Parameters, &openapi3.ParameterRef{
						Value: &openapi3.Parameter{
							Name:     paramName,
							In:       "path",
							Required: true,
							Schema: &openapi3.SchemaRef{
								Value: &openapi3.Schema{
									Type:    &openapi3.Types{openapi3.TypeString},
									Pattern: param.pattern,
								},
							},
						},
					})
				}
				oas.Paths.Map()[tc.expectedPath] = pathItem
			}

			operationID := oas.getOperationID(tc.inPath, tc.method)

			if operationID != tc.expectedID {
				t.Errorf("expected operation ID %s, got %s", tc.expectedID, operationID)
			}

			pathItem, ok := oas.Paths.Map()[tc.expectedPath]
			if !ok {
				t.Errorf("expected path %s to be created", tc.expectedPath)
				return
			}

			if tc.expectedParams != nil {
				if pathItem.Parameters == nil {
					t.Errorf("expected parameters for path %s, but got none", tc.expectedPath)
					return
				}

				for _, paramRef := range pathItem.Parameters {
					param := paramRef.Value
					expected, exists := tc.expectedParams[param.Name]
					if !exists {
						t.Errorf("unexpected parameter %s found", param.Name)
						continue
					}

					if param.Schema.Value.Pattern != expected.pattern {
						t.Errorf("expected pattern %s for parameter %s, got %s", expected.pattern, param.Name, param.Schema.Value.Pattern)
					}

					if param.Schema.Value.Type == nil || len(*param.Schema.Value.Type) == 0 {
						t.Errorf("parameter %s has nil or empty type", param.Name)
						continue
					}
					if (*param.Schema.Value.Type)[0] != expected.paramType {
						t.Errorf("expected type %s for parameter %s, got %s", expected.paramType, param.Name, (*param.Schema.Value.Type)[0])
					}
				}
			} else if pathItem.Parameters != nil {
				t.Errorf("did not expect parameters for path %s, but found some", tc.expectedPath)
			}
		})
	}
}
