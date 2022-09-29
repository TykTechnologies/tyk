package gateway

import (
	"bytes"
	"io"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef/oas"
	header "github.com/TykTechnologies/tyk/headers"
)

func (p *ReverseProxy) mockResponse(r *http.Request) (*http.Response, error) {
	route, _, _ := p.TykAPISpec.OASRouter.FindRoute(r)
	if route == nil {
		return nil, nil
	}

	operation := p.TykAPISpec.OAS.GetTykExtension().Middleware.Operations[route.Operation.OperationID]
	if operation == nil || !operation.MockResponse.Enabled {
		return nil, nil
	}

	res := &http.Response{Header: http.Header{}}

	var code int
	var contentType string
	var body []byte
	var headers map[string]string

	tykMockRespOp := p.TykAPISpec.OAS.GetTykExtension().Middleware.Operations[route.Operation.OperationID].MockResponse

	code, body, headers = mockFromConfig(tykMockRespOp)

	for key, val := range headers {
		res.Header.Set(key, val)
	}

	if contentType != "" {
		res.Header.Set(header.ContentType, contentType)
	}

	res.StatusCode = code

	res.Body = io.NopCloser(bytes.NewBuffer(body))

	return res, nil
}

func mockFromConfig(tykMockRespOp *oas.MockResponse) (int, []byte, map[string]string) {
	code := tykMockRespOp.Code
	if code == 0 {
		code = http.StatusOK
	}

	body := []byte(tykMockRespOp.Body)
	headers := tykMockRespOp.Headers

	return code, body, headers
}
