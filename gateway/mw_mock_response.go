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
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/common/option"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

var _ TykMiddleware = (*mockResponseMiddleware)(nil)

type mockResponseMiddleware struct {
	*BaseMiddleware
	hitRecorder hitRecorder
}

func newMockResponseMiddleware(base *BaseMiddleware, opts ...option.Option[mockResponseMiddleware]) TykMiddleware {
	return option.New(opts).Build(mockResponseMiddleware{
		BaseMiddleware: base,
		hitRecorder:    &realHitRecorder{successHandler: &SuccessHandler{base.Copy()}},
	})
}

func withHitRecorder(h hitRecorder) option.Option[mockResponseMiddleware] {
	return func(m *mockResponseMiddleware) {
		m.hitRecorder = h
	}
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
	start := time.Now()

	if !m.Spec.hasActiveMock() {
		return nil, http.StatusOK
	}

	res, requestOverwritten, err := m.mockResponse(r)

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

	m.hitRecorder.hit(rw, requestOverwritten, res, start)

	return nil, middleware.StatusRespond
}

func (m *mockResponseMiddleware) mockResponse(r *http.Request) (
	res *http.Response,
	internal *http.Request,
	err error,
) {
	// Use FindSpecMatchesStatus to check if this path should be mocked
	// This ensures the standard regex-based path matching is used, respecting gateway configurations
	versionInfo, _ := m.Spec.Version(r)
	versionPaths := m.Spec.RxPaths[versionInfo.Name]

	urlSpec, found := m.Spec.FindSpecMatchesStatus(r, versionPaths, OASMockResponse)

	if !found || urlSpec == nil {
		// No mock response configured for this path
		return nil, nil, nil
	}

	// Resolve the mock response config and OAS path. When multiple candidates
	// exist (collapsed parameterized paths), disambiguate using path param schemas.
	mockResponse, oasPath := m.resolveMockCandidate(r, urlSpec)
	if mockResponse == nil || !mockResponse.Enabled {
		return nil, nil, nil
	}

	res = &http.Response{Header: http.Header{}}

	internal = r.Clone(r.Context())
	internal.URL.Path = oasPath

	var code int
	var contentType string
	var body []byte
	var headers []oas.Header

	if mockResponse.FromOASExamples != nil && mockResponse.FromOASExamples.Enabled {
		// Find the route using the OAS path from URLSpec, not the actual request path.
		// This allows prefix/suffix matching to work correctly.
		strippedPath := m.Spec.StripListenPath(r.URL.Path)
		route, _, routeErr := m.Spec.findRouteForOASPath(oasPath, urlSpec.OASMethod, strippedPath, r.URL.Path)
		if routeErr != nil || route == nil {
			log.Tracef("URL spec matched for mock response but route not found for OAS path %s: %v", oasPath, routeErr)
			return nil, nil, nil
		}
		code, contentType, body, headers, err = mockFromOAS(r, route.Operation, mockResponse.FromOASExamples)
		res.StatusCode = code
		if err != nil {
			return res, internal, fmt.Errorf("mock: %w", err)
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
	res.Body = nopCloser{ReadSeeker: bytes.NewReader(body)}

	if m.Gw.GetConfig().CloseConnections {
		res.Header.Set(header.Connection, "close")
	}

	m.Spec.sendRateLimitHeaders(ctxGetSession(r), res)

	return res, internal, nil
}

// resolveMockCandidate returns the mock response config and OAS path to use.
// When the URLSpec has collapsed candidates, it disambiguates using matchCandidatePath.
// When there are no candidates, it returns the URLSpec's own config.
func (m *mockResponseMiddleware) resolveMockCandidate(r *http.Request, urlSpec *URLSpec) (*oas.MockResponse, string) {
	if len(urlSpec.OASMockResponseCandidates) == 0 {
		return urlSpec.OASMockResponseMeta, urlSpec.OASPath
	}

	strippedPath := m.Spec.StripListenPath(r.URL.Path)

	for _, candidate := range urlSpec.OASMockResponseCandidates {
		if candidate.OASMockResponseMeta == nil || !candidate.OASMockResponseMeta.Enabled {
			continue
		}

		if _, _, _, ok := m.Spec.matchCandidatePath(candidate.OASPath, candidate.OASMethod, strippedPath); ok {
			return candidate.OASMockResponseMeta, candidate.OASPath
		}
	}

	// No candidate matched — don't mock.
	return nil, ""
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
	// If none found, return fallback solution
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

	// Nil check: if no example found, return error
	if example == nil {
		example = oas.ExampleExtractor(media.Schema)
	}

	// Marshal the example to JSON for the response body
	body, err := json.Marshal(example)
	if err != nil {
		return http.StatusForbidden, "", nil, nil, err
	}

	return code, contentType, body, headers, err
}

type hitRecorder interface {
	hit(rw http.ResponseWriter, r *http.Request, res *http.Response, start time.Time)
}

type realHitRecorder struct {
	successHandler *SuccessHandler
}

func (s *realHitRecorder) hit(_ http.ResponseWriter, r *http.Request, res *http.Response, start time.Time) {
	if s.successHandler.Spec.DoNotTrack {
		return
	}

	ms := DurationToMillisecond(time.Since(start))
	latency := analytics.Latency{Total: int64(ms), Upstream: 0, Gateway: int64(ms)}
	s.successHandler.RecordHit(r, latency, res.StatusCode, res, true)
	s.successHandler.RecordAccessLog(r, res, latency)
}
