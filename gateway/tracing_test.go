package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/mccutchen/go-httpbin/v2/httpbin"
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

func TestTraceHttpRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testServer := httptest.NewServer(httpbin.New())
	defer testServer.Close()

	t.Run("#toRequest", func(t *testing.T) {
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
	})

	t.Run("api-scoped rate limit works as expected", func(t *testing.T) {
		oasDef, err := oas.NewOas(
			oas.WithTestDefaults(),
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
				Path:   "/test/rate-limited-api",
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

		defer func() {
			_ = tResponse.Body.Close()
		}()

		// Verify rate limit response
		assert.Equal(t, http.StatusTooManyRequests, tResponse.StatusCode)
		require.True(t, lo.SomeBy(logs, func(item traceLogEntry) bool {
			return strings.Contains(item.Msg, "API Rate Limit Exceeded")
		}))
	})

	t.Run("endpoint-scoped rate limit middleware works as expected", func(t *testing.T) {
		oasDef, err := oas.NewOas(
			oas.WithTestDefaults(),
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
	})

	t.Run("mock middleware works as expected", func(t *testing.T) {
		type typedResponse struct {
			Message string `json:"message"`
		}

		srcMessage := typedResponse{
			Message: "knock knock this is mock",
		}

		msgJson, err := json.Marshal(srcMessage)
		require.NoError(t, err)

		oasDef, err := oas.NewOas(
			oas.WithTestDefaults(),
			oas.WithGet("/mock", func(b *oas.EndpointBuilder) {
				b.Mock(func(mock *oas.MockResponse) {
					mock.Code = http.StatusCreated
					mock.Body = string(msgJson)
					mock.Headers = append(mock.Headers, oas.Header{Name: "hello", Value: "world"})
					mock.Headers = append(mock.Headers, oas.Header{Name: "Content-Type", Value: "application/json"})
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
	})

	t.Run("responds with log request/response logs", func(t *testing.T) {
		type HeaderCnf struct {
			Name  string
			Value string
		}

		type UuidDto struct {
			Uuid string `json:"uuid"`
		}

		type WrappedUuidDto struct {
			Data UuidDto `json:"data"`
		}

		var hdr = HeaderCnf{Name: "Content-Type", Value: "application/json"}

		oasDef, err := oas.NewOas(
			oas.WithTestDefaults(),
			oas.WithUpstreamUrl(testServer.URL),
			oas.WithGet("/uuid", func(b *oas.EndpointBuilder) {
				b.
					TransformResponseHeaders(func(headers *oas.TransformHeaders) {
						headers.AppendAddOp(hdr.Name, hdr.Value)
					}).
					TransformResponseBody(func(tb *oas.TransformBody) {
						tb.Enabled = true
						tb.Format = apidef.RequestJSON
						tb.Body = base64.StdEncoding.EncodeToString([]byte(`{"data": {{ . | toJSON }}}`))
					})
			}),
		)

		require.NoError(t, err)
		require.NotNil(t, oasDef)

		traceReq := traceRequest{
			Request: &traceHttpRequest{
				Method: http.MethodGet,
				Path:   "/uuid",
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
		require.Equal(t, http.StatusOK, response.StatusCode)

		logs, err := traceResp.logs()
		assert.NoError(t, err)

		assert.Greater(t, lo.CountBy(logs, byType(traceLogResponse)), 0)
		assert.True(t, lo.CountBy(logs, byMiddleware(new(HeaderInjector).Name())) > 0, "at least one mw log exist")
		assert.Equal(t, response.Header.Values(hdr.Name), []string{hdr.Value})

		responseBody, err := io.ReadAll(response.Body)
		require.NoError(t, err)

		// todo: should be replace by other struct cause of builder does not work properly
		var uuidDto UuidDto
		require.NoError(t, json.Unmarshal(responseBody, &uuidDto))

		require.True(t, lo.CountBy(logs, byMiddleware(new(ResponseTransformMiddleware).Name())) > 0)
		require.NoError(t, uuid.Validate(uuidDto.Uuid))
	})
}

type cntPredicate[T any] func(T) bool

func byType(typ traceLogType) cntPredicate[traceLogEntry] {
	return func(entry traceLogEntry) bool {
		return entry.Type == typ
	}
}

func byMiddleware(mwName string) cntPredicate[traceLogEntry] {
	return func(entry traceLogEntry) bool {
		return entry.Mw == mwName
	}
}
