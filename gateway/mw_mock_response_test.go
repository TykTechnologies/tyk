package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/test"
)

func TestMockResponse(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	const operationID = "my-mock-response"
	const body = "my-mock-response-body"
	const headerKey = "my-mock-response-header-key"
	const headerValue = "my-mock-response-header-value"

	mockResponse := &oas.MockResponse{
		Enabled: true,
		Code:    http.StatusTeapot,
		Body:    body,
		Headers: []oas.Header{
			{
				Name:  headerKey,
				Value: headerValue,
			},
		},
		FromOASExamples: &oas.FromOASExamples{},
	}

	xTyk := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				operationID: {
					MockResponse: mockResponse,
				},
			},
		},
	}

	oasDoc := oas.OAS{}
	oasDoc.OpenAPI = "3.0.3"
	oasDoc.Info = &openapi3.Info{
		Version: "1",
		Title:   "title",
	}

	desc := "desc"
	responses := func() *openapi3.Responses {
		responses := openapi3.NewResponses()
		responses.Delete("default")

		responses.Set("200", &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Description: &desc,
				Content: openapi3.Content{
					"application/json": &openapi3.MediaType{
						Examples: openapi3.Examples{
							"engineer": &openapi3.ExampleRef{
								Value: &openapi3.Example{
									Value: "Furkan",
								},
							},
						},
					},
				},
			},
		})

		return responses
	}()

	paths := openapi3.NewPaths()
	paths.Set("/get", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: operationID,
			Responses:   responses,
		},
	})

	oasDoc.Paths = paths

	err := oasDoc.Validate(context.Background())
	assert.NoError(t, err)

	oasDoc.SetTykExtension(xTyk)

	t.Run("from config", func(t *testing.T) {
		api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.IsOAS = true
			spec.OAS = oasDoc
		})[0]

		headersMatch := map[string]string{
			headerKey: headerValue,
		}

		_, _ = g.Run(t, test.TestCase{Path: "/get", BodyMatch: body, HeadersMatch: headersMatch, Code: http.StatusTeapot})
		_, _ = g.Run(t, test.TestCase{Path: "/elma", BodyMatch: "/elma", Code: http.StatusOK})

		api.UseKeylessAccess = false
		g.Gw.LoadAPI(api)
		_, _ = g.Run(t, test.TestCase{Path: "/get", BodyMatch: "Authorization field missing", Code: http.StatusUnauthorized})
	})

	t.Run("from OAS", func(t *testing.T) {
		mockResponse.FromOASExamples.Enabled = true
		api := BuildAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/listen-path/"
			spec.Proxy.StripListenPath = false
			spec.IsOAS = true
			spec.OAS = oasDoc
		})[0]

		g.Gw.LoadAPI(api)

		_, _ = g.Run(t, test.TestCase{Path: "/listen-path/get", BodyMatch: "Furkan", Code: http.StatusOK})
		_, _ = g.Run(t, test.TestCase{Path: "/listen-path/elma", BodyMatch: "/elma", Code: http.StatusOK})

		t.Run("strip listen path", func(t *testing.T) {
			api.Proxy.StripListenPath = true
			g.Gw.LoadAPI(api)

			_, _ = g.Run(t, test.TestCase{Path: "/listen-path/get", BodyMatch: "Furkan", Code: http.StatusOK})
			_, _ = g.Run(t, test.TestCase{Path: "/listen-path/elma", BodyMatch: "/elma", Code: http.StatusOK})
		})

		t.Run("not found", func(t *testing.T) {
			mockResponse.FromOASExamples.ContentType = "application/xml"
			g.Gw.LoadAPI(api)

			_, _ = g.Run(t, test.TestCase{Path: "/listen-path/get", BodyMatch: "mock: there is no example response for the content type: application/xml"})
		})
	})
}

func Test_mockFromConfig(t *testing.T) {
	const body = "my-mock-response-body"

	expectedHeaders := []oas.Header{
		{
			Name:  "key",
			Value: "value",
		},
	}

	tykMockRespOp := &oas.MockResponse{
		Enabled: true,
		Code:    http.StatusTeapot,
		Body:    body,
		Headers: expectedHeaders,
	}

	resCode, resBody, resHeaders := mockFromConfig(tykMockRespOp)

	assert.Equal(t, http.StatusTeapot, resCode)
	assert.Equal(t, body, string(resBody))
	assert.Equal(t, expectedHeaders, resHeaders)

	t.Run("code empty case", func(t *testing.T) {
		tykMockRespOp.Code = 0
		resCode, _, _ = mockFromConfig(tykMockRespOp)

		assert.Equal(t, http.StatusOK, resCode)
	})
}

func Test_mockFromOAS(t *testing.T) {
	fromOASExamples := &oas.FromOASExamples{}
	operation := openapi3.NewOperation()
	responses := openapi3.NewResponses()
	responses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Headers: openapi3.Headers{
				"Test-header-1": &openapi3.HeaderRef{
					Value: &openapi3.Header{
						Parameter: openapi3.Parameter{
							Schema: &openapi3.SchemaRef{
								Value: &openapi3.Schema{
									Example: "test-header-value-1",
								},
							},
						},
					},
				},
				"Test-header-2": &openapi3.HeaderRef{
					Value: &openapi3.Header{
						Parameter: openapi3.Parameter{
							Schema: &openapi3.SchemaRef{
								Value: &openapi3.Schema{
									Example: "test-header-value-2",
								},
							},
						},
					},
				},
			},
			Content: openapi3.Content{
				"application/json": {
					Example: "Furkan",
				},
			},
		},
	})
	responses.Set("208", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Content: openapi3.Content{
				"application/xml": {
					Example: "test-example-1",
				},
			},
		},
	})
	responses.Set("418", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Content: openapi3.Content{
				"text": {
					Example: "test-example-2",
				},
			},
		},
	})
	responses.Set("404", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Content: openapi3.Content{
				"text": {
					Examples: openapi3.Examples{
						"first": &openapi3.ExampleRef{
							Value: &openapi3.Example{
								Value: "first-value",
							},
						},
						"second": &openapi3.ExampleRef{
							Value: &openapi3.Example{
								Value: "second-value",
							},
						},
					},
				},
			},
		},
	})
	responses.Set("405", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Content: openapi3.Content{
				"text": {
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Example: 5,
						},
					},
				},
			},
		},
	})
	operation.Responses = responses

	t.Run("select by config", func(t *testing.T) {
		t.Run("empty config", func(t *testing.T) {
			code, contentType, body, headers, err := mockFromOAS(&http.Request{}, operation, fromOASExamples)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusOK, code)
			assert.Equal(t, "application/json", contentType)
			assert.Equal(t, `"Furkan"`, string(body))

			expectedHeaders := []oas.Header{
				{Name: "Test-header-1", Value: "test-header-value-1"},
				{Name: "Test-header-2", Value: "test-header-value-2"},
			}
			assert.Equal(t, expectedHeaders, headers)
		})

		t.Run("filled config", func(t *testing.T) {
			fromOASExamples.Code = http.StatusAlreadyReported
			fromOASExamples.ContentType = "application/xml"
			code, contentType, body, headers, err := mockFromOAS(&http.Request{}, operation, fromOASExamples)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusAlreadyReported, code)
			assert.Equal(t, "application/xml", contentType)
			assert.Equal(t, `"test-example-1"`, string(body))
			assert.Len(t, headers, 0)
		})
	})

	t.Run("override config by request", func(t *testing.T) {
		request := &http.Request{Header: http.Header{}}
		request.Header.Set(header.Accept, "text")
		request.Header.Set(header.XTykAcceptExampleCode, "418")
		code, contentType, body, _, err := mockFromOAS(request, operation, fromOASExamples)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusTeapot, code)
		assert.Equal(t, "text", contentType)
		assert.Equal(t, `"test-example-2"`, string(body))
	})

	t.Run("examples", func(t *testing.T) {
		fromOASExamples.ExampleName = "first"
		fromOASExamples.Code = http.StatusNotFound
		fromOASExamples.ContentType = "text"
		code, contentType, body, _, err := mockFromOAS(&http.Request{}, operation, fromOASExamples)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusNotFound, code)
		assert.Equal(t, "text", contentType)
		assert.Equal(t, `"first-value"`, string(body))

		t.Run("by request", func(t *testing.T) {
			request := &http.Request{Header: http.Header{}}
			request.Header.Set(header.XTykAcceptExampleName, "second")
			_, _, body, _, err := mockFromOAS(request, operation, fromOASExamples)
			assert.NoError(t, err)

			assert.Equal(t, `"second-value"`, string(body))
		})

		t.Run("randomly select", func(t *testing.T) {
			fromOASExamples.ExampleName = ""
			fromOASExamples.Code = http.StatusNotFound
			fromOASExamples.ContentType = "text"
			code, _, body, _, err = mockFromOAS(&http.Request{}, operation, fromOASExamples)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusNotFound, code)
			assert.Contains(t, []string{`"first-value"`, `"second-value"`}, string(body))
		})
	})

	t.Run("extraction from schema", func(t *testing.T) {
		fromOASExamples.ExampleName = ""
		fromOASExamples.Code = http.StatusMethodNotAllowed
		fromOASExamples.ContentType = "text"
		code, _, body, _, err := mockFromOAS(&http.Request{}, operation, fromOASExamples)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusMethodNotAllowed, code)
		assert.Equal(t, "5", string(body))
	})

	t.Run("errors", func(t *testing.T) {
		t.Run("content type", func(t *testing.T) {
			request := &http.Request{Header: http.Header{}}
			request.Header.Set(header.Accept, "undefined")
			_, _, _, _, err := mockFromOAS(request, operation, fromOASExamples)
			assert.EqualError(t, err, "there is no example response for the content type: undefined")
		})

		t.Run("code", func(t *testing.T) {
			request := &http.Request{Header: http.Header{}}
			request.Header.Set(header.XTykAcceptExampleCode, "undefined")
			_, _, _, _, err := mockFromOAS(request, operation, fromOASExamples)
			assert.EqualError(t, err, "given code undefined is not a valid integer value")

			request.Header.Set(header.XTykAcceptExampleCode, "202")
			_, _, _, _, err = mockFromOAS(request, operation, fromOASExamples)
			assert.EqualError(t, err, "there is no example response for the code: 202")
		})

		t.Run("example name", func(t *testing.T) {
			request := &http.Request{Header: http.Header{}}
			request.Header.Set(header.XTykAcceptExampleCode, "404")
			request.Header.Set(header.Accept, "text")
			request.Header.Set(header.XTykAcceptExampleName, "undefined")
			_, _, _, _, err := mockFromOAS(request, operation, fromOASExamples)
			assert.EqualError(t, err, "there is no example response for the example name: undefined")
		})
	})
}

func TestMockFromOAS_ExampleHandling(t *testing.T) {
	t.Run("handles various example sources correctly", func(t *testing.T) {
		// Create a test operation with multiple types of examples
		operation := openapi3.NewOperation()
		responses := openapi3.NewResponses()

		// 1. Response with direct example on media type
		responses.Set("200", &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Content: openapi3.Content{
					"application/json": {
						Example: map[string]interface{}{
							"name": "Direct Example",
							"type": "direct",
						},
					},
				},
			},
		})

		// 2. Response with examples in Examples map
		responses.Set("201", &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Content: openapi3.Content{
					"application/json": {
						Examples: openapi3.Examples{
							"example1": &openapi3.ExampleRef{
								Value: &openapi3.Example{
									Value: map[string]interface{}{
										"name": "Example from Map",
										"type": "examples_map",
										"id":   1,
									},
								},
							},
							"example2": &openapi3.ExampleRef{
								Value: &openapi3.Example{
									Value: map[string]interface{}{
										"name": "Second Example from Map",
										"type": "examples_map",
										"id":   2,
									},
								},
							},
						},
					},
				},
			},
		})

		// 3. Response with schema example
		responses.Set("202", &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Content: openapi3.Content{
					"application/json": {
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Example: map[string]interface{}{
									"name": "Example from Schema",
									"type": "schema",
								},
							},
						},
					},
				},
			},
		})

		// 4. Response with both direct example and examples map
		responses.Set("203", &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Content: openapi3.Content{
					"application/json": {
						Example: map[string]interface{}{
							"name": "Direct Example with Map",
							"type": "direct_with_map",
							"id":   0,
						},
						Examples: openapi3.Examples{
							"mapExample": &openapi3.ExampleRef{
								Value: &openapi3.Example{
									Value: map[string]interface{}{
										"name": "Map Example with Direct",
										"type": "map_with_direct",
										"id":   1,
									},
								},
							},
						},
					},
				},
			},
		})

		operation.Responses = responses

		// Test cases
		testCases := []struct {
			name           string
			responseCode   int
			exampleName    string
			expectedBody   string
			expectedStatus int
		}{
			{
				name:         "direct example",
				responseCode: 200,
				expectedBody: `{"name":"Direct Example","type":"direct"}`,
			},
			{
				name:         "examples map without specifying name",
				responseCode: 201,
				expectedBody: `{"id":1,"name":"Example from Map","type":"examples_map"}`,
			},
			{
				name:         "examples map with specific example",
				responseCode: 201,
				exampleName:  "example2",
				expectedBody: `{"id":2,"name":"Second Example from Map","type":"examples_map"}`,
			},
			{
				name:         "schema example",
				responseCode: 202,
				expectedBody: `{"name":"Example from Schema","type":"schema"}`,
			},
			{
				name:         "prioritizes direct example over examples map",
				responseCode: 203,
				expectedBody: `{"id":0,"name":"Direct Example with Map","type":"direct_with_map"}`,
			},
			{
				name:           "handles non-existent example name",
				responseCode:   201,
				exampleName:    "nonexistent",
				expectedStatus: http.StatusNotFound,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				fromOASExamples := &oas.FromOASExamples{
					Code:        tc.responseCode,
					ExampleName: tc.exampleName,
				}

				req := &http.Request{Header: http.Header{}}
				code, contentType, body, _, err := mockFromOAS(req, operation, fromOASExamples)

				if tc.expectedStatus != 0 {
					assert.Error(t, err)
					assert.Equal(t, tc.expectedStatus, code)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tc.responseCode, code)
					assert.Equal(t, "application/json", contentType)
					assert.JSONEq(t, tc.expectedBody, string(body))
				}
			})
		}
	})

	t.Run("fallback handling does not respond with error if example is not provided", func(t *testing.T) {
		// Test the fallback behavior when examples aren't available
		operation := openapi3.NewOperation()
		responses := openapi3.NewResponses()

		// Empty content
		responses.Set("200", &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Content: openapi3.Content{
					"application/json": {
						// Nothing defined - no example, no examples map, no schema
					},
				},
			},
		})

		// Empty examples map
		responses.Set("201", &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Content: openapi3.Content{
					"application/json": {
						Examples: openapi3.Examples{},
					},
				},
			},
		})

		operation.Responses = responses

		fromOASExamples := &oas.FromOASExamples{
			Code: 200,
		}

		req := &http.Request{Header: http.Header{}}
		code, _, _, _, err := mockFromOAS(req, operation, fromOASExamples)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)

		// Test with empty examples map
		fromOASExamples.Code = http.StatusCreated
		code, _, _, _, err = mockFromOAS(req, operation, fromOASExamples)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, code)
	})
}

func TestMockResponseWithInternalRedirect(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	firstApi := BuildOASAPI(func(oasDef *oas.OAS) {
		opId := uuid.New()

		headers := oas.Headers{}
		headers.Add("Content-Type", "application/json")

		tykExt := oasDef.GetTykExtension()
		tykExt.Info.ID = "v1-api-name"
		tykExt.Info.Name = "v1-api-name"
		tykExt.Server.ListenPath.Value = "/v1-api-name"
		tykExt.Middleware = &oas.Middleware{}
		tykExt.Middleware.Operations = oas.Operations{}
		tykExt.Middleware.Operations[opId] = &oas.Operation{
			MockResponse: &oas.MockResponse{
				Enabled: true,
				Code:    201,
				Body:    "[null]",
				Headers: headers,
			},
		}

		desc := "hello world"
		responses := openapi3.NewResponses()
		responses.Delete("default")
		responses.Set("200", &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Description: &desc,
				Content: openapi3.Content{
					"application/json": &openapi3.MediaType{},
				},
			},
		})

		oasDef.Paths = openapi3.NewPaths()
		oasDef.Paths.Set("/hello", &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: opId,
				Responses:   responses,
			},
		})
	})[0]

	//Create second API that redirects to the first API
	secondAPI := BuildOASAPI(func(oasDef *oas.OAS) {
		tykExt := oasDef.GetTykExtension()
		tykExt.Info.ID = "test_redirect"
		tykExt.Info.Name = "Test Redirect API"
		tykExt.Server.ListenPath.Value = "/test_redirect"
		tykExt.Server.ListenPath.Strip = true
		tykExt.Upstream.URL = "tyk://v1-api-name"
	})[0]

	for spec := range ts.Gw.LoadAPI(firstApi, secondAPI) {
		require.NotNil(t, spec, "expected to load api properly")
	}

	t.Run("direct request should respond with mocked data", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{
			Path:   "/v1-api-name/hello",
			Method: http.MethodGet,
			Code:   201,
		})
	})

	// Test case: Request to the second API should return the mocked response from the first API
	t.Run("Request to second API should return mocked response from first API", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{
			Path:   "/test_redirect/hello",
			Method: http.MethodGet,
			Code:   201,
		})
	})
}
