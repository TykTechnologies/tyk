package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef/oas"
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
		Headers: map[string]string{
			headerKey: headerValue,
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
	responses := openapi3.NewResponses()
	responses["200"] = &openapi3.ResponseRef{
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
	}

	oasDoc.Paths = openapi3.Paths{
		"/get": {
			Get: &openapi3.Operation{
				OperationID: operationID,
				Responses:   responses,
			},
		},
	}

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

	expectedHeaders := map[string]string{
		"key": "value",
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
	operation.Responses = openapi3.Responses{
		"200": &openapi3.ResponseRef{
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
		},
		"208": &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Content: openapi3.Content{
					"application/xml": {
						Example: "test-example-1",
					},
				},
			},
		},
		"418": &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Content: openapi3.Content{
					"text": {
						Example: "test-example-2",
					},
				},
			},
		},
		"404": &openapi3.ResponseRef{
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
		},
		"405": &openapi3.ResponseRef{
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
		},
	}

	t.Run("select by config", func(t *testing.T) {
		t.Run("empty config", func(t *testing.T) {
			code, contentType, body, headers, err := mockFromOAS(&http.Request{}, operation, fromOASExamples)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusOK, code)
			assert.Equal(t, "application/json", contentType)
			assert.Equal(t, `"Furkan"`, string(body))

			expectedHeaders := map[string]string{
				"Test-header-1": "test-header-value-1",
				"Test-header-2": "test-header-value-2",
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
		request.Header.Set(acceptContentType, "text")
		request.Header.Set(acceptCode, "418")
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
			request.Header.Set(acceptExampleName, "second")
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
			request.Header.Set(acceptContentType, "undefined")
			_, _, _, _, err := mockFromOAS(request, operation, fromOASExamples)
			assert.EqualError(t, err, "there is no example response for the content type: undefined")
		})

		t.Run("code", func(t *testing.T) {
			request := &http.Request{Header: http.Header{}}
			request.Header.Set(acceptCode, "undefined")
			_, _, _, _, err := mockFromOAS(request, operation, fromOASExamples)
			assert.EqualError(t, err, "given code undefined is not a valid integer value")

			request.Header.Set(acceptCode, "202")
			_, _, _, _, err = mockFromOAS(request, operation, fromOASExamples)
			assert.EqualError(t, err, "there is no example response for the code: 202")
		})

		t.Run("example name", func(t *testing.T) {
			request := &http.Request{Header: http.Header{}}
			request.Header.Set(acceptCode, "404")
			request.Header.Set(acceptContentType, "text")
			request.Header.Set(acceptExampleName, "undefined")
			_, _, _, _, err := mockFromOAS(request, operation, fromOASExamples)
			assert.EqualError(t, err, "there is no example response for the example name: undefined")
		})
	})
}
