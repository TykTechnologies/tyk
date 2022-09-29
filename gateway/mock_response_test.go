package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestMockResponse(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	const operationID = "my-mock-response"
	const body = "my-mock-response-body"
	const headerKey = "my-mock-response-header-key"
	const headerValue = "my-mock-response-header-value"

	xTyk := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				operationID: {
					MockResponse: &oas.MockResponse{
						Enabled: true,
						Code:    http.StatusTeapot,
						Body:    body,
						Headers: map[string]string{
							headerKey: headerValue,
						},
					},
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
	oasDoc.Paths = openapi3.Paths{
		"/get": {
			Get: &openapi3.Operation{
				OperationID: operationID,
				Responses:   openapi3.NewResponses(),
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
