package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/common/option"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

var _ TykMiddleware = (*mockResponseMiddleware)(nil)

type mockResponseMiddleware struct {
	*BaseMiddleware
}

func newMockResponseMiddleware(base *BaseMiddleware, opts ...option.Option[mockResponseMiddleware]) TykMiddleware {
	return option.New(opts).Build(mockResponseMiddleware{
		BaseMiddleware: base,
	})
}

func (m *mockResponseMiddleware) Name() string {
	return "MockResponseMiddleware"
}

func (m *mockResponseMiddleware) EnabledForSpec() bool {
	return m.Spec.hasActiveMock()
}

func (m *mockResponseMiddleware) forward(res *http.Response, rw http.ResponseWriter) error {
	for key, values := range res.Header {
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}

	rw.WriteHeader(res.StatusCode)
	if res.Body == nil {
		return nil
	}

	body, err := io.ReadAll(res.Body)

	if err != nil {
		return err
	}

	_, err = rw.Write(body)

	return err
}

func (m *mockResponseMiddleware) ProcessRequest(rw http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if !m.Spec.hasActiveMock() {
		return nil, http.StatusOK
	}

	res, err := m.mockResponse(r)

	if err != nil {
		return fmt.Errorf("failed to mock response: %w", err), http.StatusInternalServerError
	}

	if res == nil {
		return nil, http.StatusOK
	}

	if abortForward, err := handleResponseChain(m.Spec.ResponseChain, rw, res, r, ctxGetSession(r)); err != nil {
		return fmt.Errorf("failed to process response chain: %w", err), http.StatusInternalServerError
	} else if abortForward {
		// response received from plugin
		return nil, middleware.StatusRespond
	}

	if err = m.forward(res, rw); err != nil {
		return fmt.Errorf("failed to forward response: %w", err), http.StatusInternalServerError
	}

	return nil, middleware.StatusRespond
}

func (m *mockResponseMiddleware) mockResponse(r *http.Request) (*http.Response, error) {
	// if response is nil we go further
	operation := m.Spec.findOperation(r)

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

	m.Spec.sendRateLimitHeaders(ctxGetSession(r), res)

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

func mockFromOAS(r *http.Request, operation *openapi3.Operation, fromOASExamples *oas.FromOASExamples) (int, string, []byte, []oas.Header, error) {
	exampleName := fromOASExamples.ExampleName
	if headerExampleName := r.Header.Get(header.XTykAcceptExampleName); headerExampleName != "" {
		exampleName = headerExampleName
	}

	code := 200
	if fromOASExamples.Code != 0 {
		code = fromOASExamples.Code
	}

	var err error
	if headerCode := r.Header.Get(header.XTykAcceptExampleCode); headerCode != "" {
		if code, err = strconv.Atoi(headerCode); err != nil {
			return http.StatusBadRequest, "", nil, nil, fmt.Errorf("given code %s is not a valid integer value", headerCode)
		}
	}

	contentType := "application/json"
	if fromOASExamples.ContentType != "" {
		contentType = fromOASExamples.ContentType
	}

	if headerContentType := r.Header.Get(header.Accept); headerContentType != "*/*" && headerContentType != "" {
		contentType = headerContentType
	}

	response := operation.Responses.Value(strconv.Itoa(code))
	if response == nil {
		return http.StatusNotFound, "", nil, nil, fmt.Errorf("there is no example response for the code: %d", code)
	}

	media := response.Value.Content.Get(contentType)
	if media == nil {
		return http.StatusNotFound, "", nil, nil, errors.New("there is no example response for the content type: " + contentType)
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

	// Example selection precedence:
	// 1. Direct example on the media type (media.Example)
	// 2. Named example from Examples map (media.Examples) - if name provided, use it; otherwise, pick first by sorted key
	// 3. Example from the schema (media.Schema.Value.Example)
	// If none found, return error
	var example interface{}

	// 1. Direct example on the media type
	if media.Example != nil {
		example = media.Example
	}

	// 2. Named or first example from Examples map (only if no direct example)
	if example == nil && len(media.Examples) > 0 {
		if exampleName != "" {
			// Use the named example if it exists
			exampleRef, ok := media.Examples[exampleName]
			if !ok || exampleRef == nil || exampleRef.Value == nil {
				return http.StatusNotFound, "", nil, nil, errors.New("there is no example response for the example name: " + exampleName)
			}
			example = exampleRef.Value.Value
		} else {
			// Deterministically select the first example by sorted key
			keys := make([]string, 0, len(media.Examples))
			for k := range media.Examples {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				ex := media.Examples[k]
				if ex != nil && ex.Value != nil {
					example = ex.Value.Value
					break
				}
			}
		}
	}

	// 3. Example from the schema
	if example == nil && media.Schema != nil && media.Schema.Value != nil && media.Schema.Value.Example != nil {
		example = media.Schema.Value.Example
	}

	// Nil check: if no example found, return error
	if example == nil {
		return http.StatusNotFound, "", nil, nil, errors.New("there is no example response for the content type: " + contentType)
	}

	// Marshal the example to JSON for the response body
	body, err := json.Marshal(example)
	if err != nil {
		return http.StatusForbidden, "", nil, nil, err
	}

	return code, contentType, body, headers, err
}
