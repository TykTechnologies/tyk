package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	header "github.com/TykTechnologies/tyk/header"
)

const acceptContentType = "Accept"
const acceptCode = "X-Tyk-Accept-Example-Code"
const acceptExampleName = "X-Tyk-Accept-Example-Name"

func (p *ReverseProxy) mockResponse(r *http.Request) (*http.Response, error) {
	route, _, err := p.TykAPISpec.OASRouter.FindRoute(r)
	if route == nil || err != nil {
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

	tykExampleRespOp := p.TykAPISpec.OAS.GetTykExtension().Middleware.Operations[route.Operation.OperationID].MockResponse

	if tykExampleRespOp.FromOASExamples != nil && tykExampleRespOp.FromOASExamples.Enabled {
		code, contentType, body, headers, err = mockFromOAS(r, route.Operation, tykExampleRespOp.FromOASExamples)
		res.StatusCode = code
		if err != nil {
			err = fmt.Errorf("mock: %s", err)
			return res, err
		}
	} else {
		code, body, headers = mockFromConfig(tykExampleRespOp)
	}

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

func mockFromOAS(r *http.Request, operation *openapi3.Operation, fromOASExamples *oas.FromOASExamples) (int, string, []byte, map[string]string, error) {
	exampleName := fromOASExamples.ExampleName
	if headerExampleName := r.Header.Get(acceptExampleName); headerExampleName != "" {
		exampleName = headerExampleName
	}

	code := 200
	if fromOASExamples.Code != 0 {
		code = fromOASExamples.Code
	}

	var err error
	if headerCode := r.Header.Get(acceptCode); headerCode != "" {
		if code, err = strconv.Atoi(headerCode); err != nil {
			return http.StatusBadRequest, "", nil, nil, fmt.Errorf("given code %s is not a valid integer value", headerCode)
		}
	}

	contentType := "application/json"
	if fromOASExamples.ContentType != "" {
		contentType = fromOASExamples.ContentType
	}

	if headerContentType := r.Header.Get(acceptContentType); headerContentType != "*/*" && headerContentType != "" {
		contentType = headerContentType
	}

	response, ok := operation.Responses[strconv.Itoa(code)]
	if !ok {
		return http.StatusNotFound, "", nil, nil, fmt.Errorf("there is no example response for the code: %d", code)
	}

	media := response.Value.Content.Get(contentType)
	if media == nil {
		return http.StatusNotFound, "", nil, nil, errors.New("there is no example response for the content type: " + contentType)
	}

	headers := make(map[string]string)
	for key, val := range response.Value.Headers {
		headers[key] = fmt.Sprintf("%v", oas.ExampleExtractor(val.Value.Schema))
	}

	var example interface{}
	if media.Example != nil {
		example = media.Example
	}

	if len(media.Examples) > 0 {
		if exampleName != "" {
			if exampleRef, ok := media.Examples[exampleName]; !ok {
				return http.StatusNotFound, "", nil, nil, errors.New("there is no example response for the example name: " + exampleName)
			} else {
				example = exampleRef.Value.Value
			}
		} else {
			for _, iterExample := range media.Examples {
				example = iterExample.Value.Value
				break
			}
		}
	}

	if example == nil {
		example = oas.ExampleExtractor(media.Schema)
	}

	body, err := json.Marshal(example)
	if err != nil {
		return http.StatusForbidden, "", nil, nil, err
	}

	return code, contentType, body, headers, err
}
