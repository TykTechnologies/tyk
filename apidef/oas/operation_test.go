package oas

import (
	"context"
	"embed"
	"encoding/json"
	"net/http"
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

	tests := []struct {
		name string
		spec OAS
		want func(t *testing.T, ep *apidef.ExtendedPathsSet)
	}{
		{
			name: "basic mock response",
			spec: OAS{
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
				assert.Len(t, ep.WhiteList, 1)
				mockResp := ep.WhiteList[0]
				assert.Equal(t, "/test", mockResp.Path)
				assert.Equal(t, "GET", mockResp.Method)
				require.NotNil(t, mockResp.MethodActions["GET"])
				assert.Equal(t, apidef.Reply, mockResp.MethodActions["GET"].Action)
				assert.Equal(t, 200, mockResp.MethodActions["GET"].Code)
				assert.Equal(t, `{"message": "success"}`, mockResp.MethodActions["GET"].Data)
				assert.Equal(t, map[string]string{"Content-Type": "application/json"}, mockResp.MethodActions["GET"].Headers)
				assert.False(t, mockResp.Disabled)
			},
		},
		{
			name: "multiple methods on same path",
			spec: OAS{
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
			},
			want: func(t *testing.T, ep *apidef.ExtendedPathsSet) {
				assert.Len(t, ep.WhiteList, 2)

				// Sort mock responses for consistent testing
				sort.Slice(ep.WhiteList, func(i, j int) bool {
					if ep.WhiteList[i].Path == ep.WhiteList[j].Path {
						return ep.WhiteList[i].Method < ep.WhiteList[j].Method
					}
					return ep.WhiteList[i].Path < ep.WhiteList[j].Path
				})

				// Verify GET mock response
				getMock := ep.WhiteList[0]
				assert.Equal(t, "/test", getMock.Path)
				assert.Equal(t, "GET", getMock.Method)
				require.NotNil(t, getMock.MethodActions["GET"])
				assert.Equal(t, apidef.Reply, getMock.MethodActions["GET"].Action)
				assert.Equal(t, 200, getMock.MethodActions["GET"].Code)
				assert.Equal(t, `{"status": "ok"}`, getMock.MethodActions["GET"].Data)
				assert.Equal(t, map[string]string{"Content-Type": "application/json"}, getMock.MethodActions["GET"].Headers)
				assert.False(t, getMock.Disabled)

				// Verify POST mock response
				postMock := ep.WhiteList[1]
				assert.Equal(t, "/test", postMock.Path)
				assert.Equal(t, "POST", postMock.Method)
				require.NotNil(t, postMock.MethodActions["POST"])
				assert.Equal(t, apidef.Reply, postMock.MethodActions["POST"].Action)
				assert.Equal(t, 201, postMock.MethodActions["POST"].Code)
				assert.Equal(t, `{"id": "123"}`, postMock.MethodActions["POST"].Data)
				assert.Equal(t, map[string]string{
					"Content-Type": "application/json",
					"Location":     "/test/123",
				}, postMock.MethodActions["POST"].Headers)
				assert.False(t, postMock.Disabled)
			},
		},
		{
			name: "disabled mock response",
			spec: OAS{
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
			},
			want: func(t *testing.T, ep *apidef.ExtendedPathsSet) {
				assert.Len(t, ep.WhiteList, 1)
				mockResp := ep.WhiteList[0]
				assert.Equal(t, "/test", mockResp.Path)
				assert.Equal(t, "GET", mockResp.Method)
				require.NotNil(t, mockResp.MethodActions["GET"])
				assert.Equal(t, apidef.Reply, mockResp.MethodActions["GET"].Action)
				assert.Equal(t, 404, mockResp.MethodActions["GET"].Code)
				assert.Equal(t, `{"error": "not found"}`, mockResp.MethodActions["GET"].Data)
				assert.True(t, mockResp.Disabled)
			},
		},
		{
			name: "no mock responses",
			spec: OAS{
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
									"testGET": &Operation{},
								},
							},
						},
					},
				},
			},
			want: func(t *testing.T, ep *apidef.ExtendedPathsSet) {
				assert.Empty(t, ep.MockResponse)
			},
		},
		{
			name: "multiple paths with mock responses",
			spec: OAS{
				T: openapi3.T{
					OpenAPI: DefaultOpenAPI,
					Paths: openapi3.Paths{
						"/users": {
							Get: &openapi3.Operation{
								OperationID: "usersGET",
							},
						},
						"/items": {
							Get: &openapi3.Operation{
								OperationID: "itemsGET",
							},
						},
					},
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
				assert.Len(t, ep.WhiteList, 2)

				// Sort for consistent testing
				sort.Slice(ep.WhiteList, func(i, j int) bool {
					return ep.WhiteList[i].Path < ep.WhiteList[j].Path
				})

				// Verify items response
				itemsResp := ep.WhiteList[0]
				assert.Equal(t, "/items", itemsResp.Path)
				assert.Equal(t, "GET", itemsResp.Method)
				require.NotNil(t, itemsResp.MethodActions["GET"])
				assert.Equal(t, apidef.Reply, itemsResp.MethodActions["GET"].Action)
				assert.Equal(t, 200, itemsResp.MethodActions["GET"].Code)
				assert.Equal(t, `["item1", "item2"]`, itemsResp.MethodActions["GET"].Data)
				assert.Equal(t, map[string]string{"Content-Type": "application/json"}, itemsResp.MethodActions["GET"].Headers)

				// Verify users response
				usersResp := ep.WhiteList[1]
				assert.Equal(t, "/users", usersResp.Path)
				assert.Equal(t, "GET", usersResp.Method)
				require.NotNil(t, usersResp.MethodActions["GET"])
				assert.Equal(t, apidef.Reply, usersResp.MethodActions["GET"].Action)
				assert.Equal(t, 200, usersResp.MethodActions["GET"].Code)
				assert.Equal(t, `["user1", "user2"]`, usersResp.MethodActions["GET"].Data)
				assert.Equal(t, map[string]string{"Content-Type": "application/json"}, usersResp.MethodActions["GET"].Headers)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ep apidef.ExtendedPathsSet
			tt.spec.extractPathsAndOperations(&ep)
			tt.want(t, &ep)
		})
	}
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

	tests := []struct {
		name string
		ep   apidef.ExtendedPathsSet
		want func(t *testing.T, spec *OAS)
	}{
		{
			name: "basic mock response",
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
				assert.Len(t, spec.Paths, 1)
				pathItem := spec.Paths["/test"]
				require.NotNil(t, pathItem)

				// Verify operation
				require.NotNil(t, pathItem.Get)
				assert.Equal(t, "testGET", pathItem.Get.OperationID)
				assert.Nil(t, pathItem.Post)
				assert.Nil(t, pathItem.Put)
				assert.Nil(t, pathItem.Patch)
				assert.Nil(t, pathItem.Delete)

				// Verify response
				response200Ref := pathItem.Get.Responses["200"]
				require.NotNil(t, response200Ref, "Response ref for 200 should not be nil")
				response200 := response200Ref.Value
				require.NotNil(t, response200, "Response value for 200 should not be nil")

				// Verify content
				mediaType := response200.Content["application/json"]
				require.NotNil(t, mediaType)
				require.NotNil(t, mediaType.Examples)
				example := mediaType.Examples["default"]
				require.NotNil(t, example)
				assert.Equal(t, `{"message": "success"}`, example.Value.Value)

				// Verify headers
				assert.Equal(t, "application/json", response200.Headers["Content-Type"].Value.Schema.Value.Example)
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
				assert.Len(t, spec.Paths, 1)
				pathItem := spec.Paths["/test"]
				require.NotNil(t, pathItem)

				// Verify GET operation
				require.NotNil(t, pathItem.Get)
				assert.Equal(t, "testGET", pathItem.Get.OperationID)
				response200Ref := pathItem.Get.Responses["200"]
				require.NotNil(t, response200Ref, "Response ref for 200 should not be nil")
				response200 := response200Ref.Value
				require.NotNil(t, response200, "Response value for 200 should not be nil")
				assert.Equal(t, `{"status": "ok"}`, response200.Content["application/json"].Examples["default"].Value.Value)
				assert.Equal(t, "application/json", response200.Headers["Content-Type"].Value.Schema.Value.Example)

				// Verify POST operation
				require.NotNil(t, pathItem.Post)
				assert.Equal(t, "testPOST", pathItem.Post.OperationID)
				postResponse := pathItem.Post.Responses["201"].Value
				require.NotNil(t, postResponse)
				require.NotNil(t, postResponse.Content["application/json"].Examples)
				assert.Equal(t, `{"id": "123"}`, postResponse.Content["application/json"].Examples["default"].Value.Value)
				assert.Equal(t, "application/json", postResponse.Headers["Content-Type"].Value.Schema.Value.Example)
				assert.Equal(t, "/test/123", postResponse.Headers["Location"].Value.Schema.Value.Example)
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
				pathItem := spec.Paths["/test"]
				require.NotNil(t, pathItem)
				assert.Equal(t, "testGET", pathItem.Get.OperationID)
				response204Ref := pathItem.Get.Responses["204"]
				require.NotNil(t, response204Ref, "Response ref for 204 should not be nil")
				response204 := response204Ref.Value
				require.NotNil(t, response204, "Response value for 204 should not be nil")
				require.NotNil(t, response204.Content["text/plain"])
				require.NotNil(t, response204.Content["text/plain"].Examples)
				assert.Equal(t, "", response204.Content["text/plain"].Examples["default"].Value.Value)
				assert.Empty(t, response204.Headers)
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
				assert.Len(t, spec.Paths, 2)

				// Verify /users path
				usersPath := spec.Paths["/users"]
				require.NotNil(t, usersPath)
				require.NotNil(t, usersPath.Get)
				assert.Equal(t, "usersGET", usersPath.Get.OperationID)
				usersResponse := usersPath.Get.Responses["200"].Value
				require.NotNil(t, usersResponse)
				assert.Equal(t, `["user1", "user2"]`, usersResponse.Content["application/json"].Examples["default"].Value.Value)

				// Verify /items path
				itemsPath := spec.Paths["/items"]
				require.NotNil(t, itemsPath)
				require.NotNil(t, itemsPath.Get)
				assert.Equal(t, "itemsGET", itemsPath.Get.OperationID)
				itemsResponse := itemsPath.Get.Responses["200"].Value
				require.NotNil(t, itemsResponse)
				assert.Equal(t, `["item1", "item2"]`, itemsResponse.Content["application/json"].Examples["default"].Value.Value)
			},
		},
		{
			name: "empty mock response list",
			ep: apidef.ExtendedPathsSet{
				MockResponse: []apidef.MockResponseMeta{},
			},
			want: func(t *testing.T, spec *OAS) {
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
				pathItem := spec.Paths["/test"]
				require.NotNil(t, pathItem)
				require.NotNil(t, pathItem.Get)
				assert.Equal(t, "testGET", pathItem.Get.OperationID)

				// Verify responses exist
				require.NotNil(t, pathItem.Get.Responses)

				// Verify 200 response
				response200 := pathItem.Get.Responses.Get(200)
				require.NotNil(t, response200, "Response for 200 should not be nil")
				mediaType200 := response200.Value.Content["application/json"]
				require.NotNil(t, mediaType200)
				require.NotNil(t, mediaType200.Examples)
				assert.Equal(t, `{"status": "success"}`, mediaType200.Examples["default"].Value.Value)
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
				// JSON endpoint
				jsonPath := spec.Paths["/test"]
				require.NotNil(t, jsonPath)
				jsonResponse := jsonPath.Get.Responses["200"].Value
				assert.Equal(t, `{"data": "json"}`, jsonResponse.Content["application/json"].Examples["default"].Value.Value)

				// XML endpoint
				xmlPath := spec.Paths["/test.xml"]
				require.NotNil(t, xmlPath)
				xmlResponse := xmlPath.Get.Responses["200"].Value
				assert.Equal(t, `<data>xml</data>`, xmlResponse.Content["application/xml"].Examples["default"].Value.Value)

				// Text endpoint
				txtPath := spec.Paths["/test.txt"]
				require.NotNil(t, txtPath)
				txtResponse := txtPath.Get.Responses["200"].Value
				assert.Equal(t, `plain text`, txtResponse.Content["text/plain"].Examples["default"].Value.Value)
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
				pathItem := spec.Paths["/test"]
				require.NotNil(t, pathItem)
				response := pathItem.Get.Responses["200"].Value
				require.NotNil(t, response)

				// Verify all headers
				expectedHeaders := map[string]string{
					"Content-Type":      "application/json",
					"X-Custom-Header":   "custom-value",
					"X-Request-ID":      "123",
					"X-Correlation-ID":  "abc",
					"Cache-Control":     "no-cache",
					"X-RateLimit-Limit": "100",
				}

				for header, value := range expectedHeaders {
					headerObj := response.Headers[http.CanonicalHeaderKey(header)]
					require.NotNil(t, headerObj, "Header %s not found", header)
					assert.Equal(t, value, headerObj.Value.Schema.Value.Example)
				}
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
				pathItem := spec.Paths["/test"]
				require.NotNil(t, pathItem)

				// Helper function to verify operation
				verifyOperation := func(op *openapi3.Operation, method string, code int, body string) {
					require.NotNil(t, op, "Operation %s should exist", method)
					require.NotNil(t, op.Responses, "Responses should not be nil")

					statusCode := strconv.Itoa(code)
					require.NotNil(t, op.Responses[statusCode], "Responses should not be nil for status code %s and method %s", statusCode, method)

					response := op.Responses[statusCode].Value
					require.NotNil(t, response)
					if body != "" {
						contentType := "text/plain" // default content type

						var jsonValue = []interface{}{
							map[string]json.RawMessage{},
							[]json.RawMessage{},
						}

						for _, value := range jsonValue {
							if err := json.Unmarshal([]byte(body), value); err == nil {
								contentType = "application/json"
								break
							}
						}

						if ct, ok := response.Headers["Content-Type"]; ok {
							contentType = ct.Value.Schema.Value.Example.(string)
						}

						require.NotNil(t, response.Content[contentType], "Content type %s not found", contentType)
						require.NotNil(t, response.Content[contentType].Examples, "Examples for content type %s not found", contentType)
						assert.Equal(t, body, response.Content[contentType].Examples["default"].Value.Value)
					}
				}

				verifyOperation(pathItem.Get, "GET", 200, `{"method":"get"}`)
				verifyOperation(pathItem.Post, "POST", 201, `{"method":"post"}`)
				verifyOperation(pathItem.Put, "PUT", 200, `{"method":"put"}`)
				verifyOperation(pathItem.Patch, "PATCH", 200, `{"method":"patch"}`)
				verifyOperation(pathItem.Delete, "DELETE", 204, ``)
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
					Paths: openapi3.Paths{},
				},
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
				path := mockResp.Path
				if spec.Paths[path] == nil {
					spec.Paths[path] = &openapi3.PathItem{}
				}

				// Initialize operation with responses
				op := &openapi3.Operation{
					OperationID: spec.getOperationID(mockResp.Path, mockResp.Method),
					Responses:   openapi3.NewResponses(),
				}

				// Set the operation based on method
				switch mockResp.Method {
				case "GET":
					spec.Paths[path].Get = op
				case "POST":
					spec.Paths[path].Post = op
				case "PUT":
					spec.Paths[path].Put = op
				case "PATCH":
					spec.Paths[path].Patch = op
				case "DELETE":
					spec.Paths[path].Delete = op
				case "HEAD":
					spec.Paths[path].Head = op
				case "OPTIONS":
					spec.Paths[path].Options = op
				}
			}

			spec.fillMockResponsePaths(spec.Paths, tt.ep)
			tt.want(t, spec)
		})
	}
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
