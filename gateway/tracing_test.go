package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/samber/lo"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
)

func TestTraceHttpRequest_toRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const body = `{"foo":"bar"}`
	var headers = http.Header{}
	headers.Add("key", "value")
	headers.Add("Content-Type", "application/json")

	tr := traceRequest{
		Request: &traceHttpRequest{Path: "", Method: http.MethodPost, Body: body, Headers: headers},
		Spec: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{
				ListenPath: "",
			},
		},
		OAS: &oas.OAS{},
	}

	request, err := tr.toRequest(ctx, ts.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey)
	assert.NoError(t, err)
	assert.NotNil(t, request)

	bodyInBytes, err := io.ReadAll(request.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.MethodPost, request.Method)
	assert.Equal(t, "", request.URL.Host)
	assert.Equal(t, "", request.URL.Path)
	assert.Equal(t, headers, request.Header)
	assert.Equal(t, string(bodyInBytes), body)
}

func TestTraceHandler_RateLimiterGlobalWorksAsExpected(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oasDef, err := oas.NewOas(
		oas.WithTestDefaults(ctx, "/test"),
		oas.WithGlobalRateLimit(1, 60*time.Second),
		oas.WithGet("/rate-limited-api", func(b *oas.EndpointBuilder) {
			b.Mock(func(_ *oas.MockResponse) {})
		}),
	)

	require.NoError(t, err)
	require.NotNil(t, oasDef)

	// Create trace request
	traceReq := traceRequest{
		Request: &traceHttpRequest{
			Method: http.MethodGet,
			Path:   "/rate-limited-api",
		},
		OAS: oasDef,
	}

	// Marshal trace request
	reqBody, err := json.Marshal(traceReq)
	require.NoError(t, err)
	require.NotNil(t, reqBody)

	// First request should succeed
	req1 := httptest.NewRequest(http.MethodPost, "/debug/trace", bytes.NewReader(reqBody))
	req1.Header.Set("Content-Type", "application/json")

	// Listen path is empty

	w1 := httptest.NewRecorder()
	ts.Gw.traceHandler(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	var traceResp1 traceResponse
	err = json.Unmarshal(w1.Body.Bytes(), &traceResp1)
	assert.NoError(t, err)

	_, tResponse1, err := traceResp1.parseTrace()
	require.NoError(t, err)

	// Verify rate limit response
	assert.Equal(t, http.StatusOK, tResponse1.StatusCode)
	logs1, err := traceResp1.logs()
	assert.NoError(t, err)
	require.True(t, lo.SomeBy(logs1, func(logEntry traceLogEntry) bool {
		return logEntry.Mw == new(mockResponseMiddleware).Name() && logEntry.Code == middleware.StatusRespond
	}))

	// Second request should be rate limited
	req2 := httptest.NewRequest(http.MethodPost, "/debug/trace", bytes.NewReader(reqBody))
	req2.Header.Set("Content-Type", "application/json")

	w2 := httptest.NewRecorder()
	ts.Gw.traceHandler(w2, req2)

	// Parse response
	var traceResp2 traceResponse
	err = json.Unmarshal(w2.Body.Bytes(), &traceResp2)
	assert.NoError(t, err)

	logs2, err := traceResp2.logs()
	require.NoError(t, err)

	_, tResponse2, err := traceResp2.parseTrace()
	require.NoError(t, err)

	// Verify rate limit response
	assert.Equal(t, http.StatusTooManyRequests, tResponse2.StatusCode)
	require.True(t, lo.SomeBy(logs2, func(item traceLogEntry) bool {
		return strings.Contains(item.Msg, "API Rate Limit Exceeded")
	}))
}

func TestTraceHandler_RateLimiterExceeded(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oasDef, err := oas.NewOas(
		oas.WithTestDefaults(ctx, "/test"),
		oas.WithGet("/rate-limited-api", func(b *oas.EndpointBuilder) {
			b.Mock(func(_ *oas.MockResponse) {}).RateLimit(1, time.Second)
		}),
	)

	require.NoError(t, err)
	require.NotNil(t, oasDef)

	// Create trace request
	traceReq := traceRequest{
		Request: &traceHttpRequest{
			Method: http.MethodGet,
			Path:   "/rate-limited-api",
		},
		OAS: oasDef,
	}

	// Marshal trace request
	reqBody, err := json.Marshal(traceReq)
	require.NoError(t, err)
	require.NotNil(t, reqBody)

	// First request should succeed
	req1 := httptest.NewRequest(http.MethodPost, "/debug/trace", bytes.NewReader(reqBody))
	req1.Header.Set("Content-Type", "application/json")
	req1 = ts.withAuth(req1)

	w1 := httptest.NewRecorder()
	ts.Gw.traceHandler(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	// Second request should be rate limited
	req2 := httptest.NewRequest(http.MethodPost, "/debug/trace", bytes.NewReader(reqBody))
	req2.Header.Set("Content-Type", "application/json")

	w2 := httptest.NewRecorder()
	ts.Gw.traceHandler(w2, req2)

	// Parse response
	var traceResp2 traceResponse
	err = json.Unmarshal(w2.Body.Bytes(), &traceResp2)
	assert.NoError(t, err)

	logs, err := traceResp2.logs()
	require.NoError(t, err)

	_, tResponse, err := traceResp2.parseTrace()
	require.NoError(t, err)

	// Verify rate limit response
	require.Equal(t, http.StatusTooManyRequests, tResponse.StatusCode)
	require.True(t, lo.SomeBy(logs, func(item traceLogEntry) bool {
		return strings.Contains(item.Msg, "API Rate Limit Exceeded")
	}))
}

func TestTraceHandler_MockMiddlewareRespondsWithProvidedData(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type typedResponse struct {
		Message string `json:"message"`
	}

	srcMessage := typedResponse{
		Message: "knock knock this is mock",
	}

	msgJson, err := json.Marshal(srcMessage)
	require.NoError(t, err)

	oasDef, err := oas.NewOas(
		oas.WithTestDefaults(ctx, "/test"),
		oas.WithGet("/mock", func(b *oas.EndpointBuilder) {
			b.Mock(func(mock *oas.MockResponse) {
				mock.Code = http.StatusCreated
				mock.Body = string(msgJson)
				mock.Headers.Add("hello", "world")
				mock.Headers.Add(header.ContentType, "application/json")
			})
		}),
	)

	require.NoError(t, err)
	require.NotNil(t, oasDef)

	// Create trace request
	traceReq := traceRequest{
		Request: &traceHttpRequest{
			Method: http.MethodGet,
			Path:   "/mock",
		},
		OAS: oasDef,
	}

	reqBody, err := json.Marshal(traceReq)
	require.NoError(t, err)
	require.NotNil(t, reqBody)

	req := httptest.NewRequest(http.MethodPost, "/debug/trace", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	res := httptest.NewRecorder()
	ts.Gw.traceHandler(res, req)
	require.Equal(t, http.StatusOK, res.Code)

	var traceResp traceResponse

	err = json.NewDecoder(res.Body).Decode(&traceResp)
	assert.NoError(t, err)

	request, response, err := traceResp.parseTrace()
	require.NoError(t, err)

	defer func() {
		_ = response.Body.Close()
	}()

	require.NotNil(t, request)
	require.NotNil(t, response)

	var mockedResponse typedResponse
	require.Equal(t, http.StatusCreated, response.StatusCode)
	err = json.NewDecoder(response.Body).Decode(&mockedResponse)
	assert.NoError(t, err)
	assert.Equal(t, srcMessage.Message, mockedResponse.Message)
}
