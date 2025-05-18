package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	header "github.com/TykTechnologies/tyk/header"
)

const acceptContentType = "Accept"
const acceptCode = "X-Tyk-Accept-Example-Code"
const acceptExampleName = "X-Tyk-Accept-Example-Name"

func (p *ReverseProxy) mockResponse(r *http.Request) (*http.Response, error) {
	operation := ctxGetOperation(r)
	if operation == nil {
		return nil, nil
	}

	mockResponse := operation.MockResponse
	if mockResponse == nil || !mockResponse.Enabled {
		return nil, nil
	}

	res := &http.Response{Header: http.Header{}}

	var code int
	var contentType string
	var body []byte
	var headers []oas.Header
	var err error

	if mockResponse.FromOASExamples != nil && mockResponse.FromOASExamples.Enabled {
		code, contentType, body, headers, err = mockFromOAS(r, operation.route.Operation, mockResponse.FromOASExamples)
		res.StatusCode = code
		if err != nil {
			err = fmt.Errorf("mock: %w", err)
			return res, err
		}
	} else {
		code, body, headers = mockFromConfig(mockResponse)
	}

	for _, h := range headers {
		res.Header.Set(h.Name, h.Value)
	}

	if contentType != "" {
		res.Header.Set(header.ContentType, contentType)
	}

	res.StatusCode = code

	res.Body = io.NopCloser(bytes.NewBuffer(body))

	return res, nil
}

func mockFromConfig(tykMockRespOp *oas.MockResponse) (int, []byte, []oas.Header) {
	code := tykMockRespOp.Code
	if code == 0 {
		code = http.StatusOK
	}

	body := []byte(tykMockRespOp.Body)
	headers := tykMockRespOp.Headers

	return code, body, headers
}

// mockFromOAS extracts example responses from an OpenAPI specification.
// It looks for examples in the following order of precedence:
// 1. Direct example on the media type object (media.Example)
// 2. Examples from the Examples map in the media type (media.Examples)
// 3. Example from the schema (media.Schema)
//
// This function will:
// - Check for and use specific examples by name if requested
// - Support header-based content negotiation and status code selection
// - Extract headers from the response definition
// - Return appropriate error messages when examples cannot be found
func mockFromOAS(r *http.Request, operation *openapi3.Operation, fromOASExamples *oas.FromOASExamples) (int, string, []byte, []oas.Header, error) {
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

	responses := operation.Responses.Map()

	response, ok := responses[strconv.Itoa(code)]
	if !ok {
		return http.StatusNotFound, "", nil, nil, fmt.Errorf("there is no example response for the code: %d", code)
	}

	media := response.Value.Content.Get(contentType)
	if media == nil {
		return http.StatusNotFound, "", nil, nil, fmt.Errorf("there is no example response for the content type: %s", contentType)
	}

	headers := make([]oas.Header, len(response.Value.Headers))
	i := 0
	for key, val := range response.Value.Headers {
		headers[i] = oas.Header{Name: key, Value: fmt.Sprintf("%v", oas.ExampleExtractor(val.Value.Schema))}
		i++
	}

	sort.Slice(headers, func(i, j int) bool {
		return headers[i].Name < headers[j].Name
	})

	// Try to find an example to use
	var example interface{}

	// First check for a direct example on the media type
	if media.Example != nil {
		example = media.Example
	} else if len(media.Examples) > 0 {
		// If we have examples in the Examples map
		if exampleName != "" {
			// If a specific example name was requested
			if exampleRef, ok := media.Examples[exampleName]; ok {
				example = exampleRef.Value.Value
			} else {
				return http.StatusNotFound, "", nil, nil, fmt.Errorf("there is no example response for the example name: %s", exampleName)
			}
		} else {
			// If no specific example was requested, use the first one
			// Sort keys for deterministic behavior
			keys := make([]string, 0, len(media.Examples))
			for k := range media.Examples {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			// Use the first example after sorting
			for _, key := range keys {
				if exampleRef := media.Examples[key]; exampleRef != nil && exampleRef.Value != nil {
					example = exampleRef.Value.Value
					break
				}
			}
		}
	}

	// If no example was found, try to extract from schema
	if example == nil && media.Schema != nil {
		example = oas.ExampleExtractor(media.Schema)
	}

	// If we still have no example, return an error
	if example == nil {
		return http.StatusNotFound, "", nil, nil, fmt.Errorf("there is no example response for the content type: %s", contentType)
	}

	body, err := json.Marshal(example)
	if err != nil {
		return http.StatusForbidden, "", nil, nil, err
	}

	return code, contentType, body, headers, nil
}
