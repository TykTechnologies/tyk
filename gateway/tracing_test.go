package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/oasbuilder"
	"github.com/google/uuid"
	"github.com/mccutchen/go-httpbin/v2/httpbin"
	"github.com/samber/lo"
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

		session := ctxGetSession(request)
		assert.NotNil(t, session, "initializes default fake session")
	})

	t.Run("api-scoped rate limit works as expected", func(t *testing.T) {
		oasDef, err := oasbuilder.Build(
			oasbuilder.WithTestListenPathAndUpstream("/test", testServer.URL),
			oasbuilder.WithGlobalRateLimit(1, 60*time.Second),
			oasbuilder.WithGet("/rate-limited-api", func(b *oasbuilder.EndpointBuilder) {
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
	})

	t.Run("endpoint-scoped rate limit middleware works as expected", func(t *testing.T) {
		oasDef, err := oasbuilder.Build(
			oasbuilder.WithTestListenPathAndUpstream("/test", testServer.URL),
			oasbuilder.WithGet("/rate-limited-api", func(b *oasbuilder.EndpointBuilder) {
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

		oasDef, err := oasbuilder.Build(
			oasbuilder.WithTestListenPathAndUpstream("/test", testServer.URL),
			oasbuilder.WithGet("/mock", func(b *oasbuilder.EndpointBuilder) {
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
	})

	t.Run("responds with log request/response logs", func(t *testing.T) {
		type HeaderCnf struct {
			Name  string
			Value string
		}

		type UuidDto struct {
			Uuid string `json:"uuid"`
		}

		var hdr = HeaderCnf{Name: "Content-Type", Value: "application/json"}

		oasDef, err := oasbuilder.Build(
			oasbuilder.WithTestListenPathAndUpstream("/test", testServer.URL),
			oasbuilder.WithGet("/uuid", func(b *oasbuilder.EndpointBuilder) {
				b.
					TransformResponseHeaders(func(headers *oas.TransformHeaders) {
						headers.AppendAddOp(hdr.Name, hdr.Value)
					}).
					TransformResponseBodyJson(`{"data": {{ . | toJSON }}}`)
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

	t.Run("transform body request writes logs", func(t *testing.T) {
		type typedResponse struct {
			Id string `json:"id"`
		}

		const (
			responseRemove       = "response-remove"
			responseAddKey       = "response-add-key"
			responseAddValue     = "response-add-value"
			requestRemove        = "request-remove"
			requestAddKey        = "request-add-key"
			requestAddValue      = "request-add-value"
			dummyUnexistentValue = "dummy-unexistent-value"
		)

		oasDef, err := oasbuilder.Build(
			oasbuilder.WithTestListenPathAndUpstream("/test", testServer.URL),
			oasbuilder.WithGlobalRateLimit(1, 60*time.Second),
			oasbuilder.WithGet("/uuid", func(b *oasbuilder.EndpointBuilder) {
				b.
					TransformResponseBodyJson(`{"id":"{{.uuid}}"}`).
					TransformResponseHeaders(func(headers *oas.TransformHeaders) {
						headers.Remove = append(headers.Remove, responseRemove)
						headers.Add.Add(responseAddKey, responseAddValue)
					}).
					TransformRequestHeaders(func(headers *oas.TransformHeaders) {
						headers.Remove = append(headers.Remove, requestRemove)
						headers.Add.Add(requestAddKey, requestAddValue)
					}).
					TransformRequestBodyJson(`{"data": {{ .input }}}`)
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
		require.NotNil(t, request)
		require.NotNil(t, response)

		var mockedResponse typedResponse
		require.Equal(t, http.StatusOK, response.StatusCode)
		err = json.NewDecoder(response.Body).Decode(&mockedResponse)
		defer response.Body.Close()
		require.NoError(t, err)
		require.NoError(t, uuid.Validate(mockedResponse.Id))

		logs, err := traceResp.logs()
		require.NoError(t, err)

		assert.Equal(t, 1, lo.CountBy(logs, and(byMsgContains(msgBodyTransformed), byType(traceLogRequest))), "contains message %q", msgBodyTransformed)
		assert.Equal(t, 1, lo.CountBy(logs, and(byMsgContains(msgBodyTransformed), byType(traceLogResponse))), "contains message %q", msgBodyTransformed)

		assert.Equal(t, 1, lo.CountBy(logs, byMsgContains(responseRemove)), "contains message %q", responseRemove)
		assert.Equal(t, 1, lo.CountBy(logs, byMsgContains(fmt.Sprintf("%s: %s", responseAddKey, responseAddValue))), "contains message %s: %s", responseAddKey, responseAddValue)

		assert.Equal(t, 1, lo.CountBy(logs, byMsgContains(requestRemove)), "contains message %q", requestRemove)
		assert.Equal(t, 1, lo.CountBy(logs, byMsgContains(fmt.Sprintf("%s: %s", requestAddKey, requestAddValue))), "contains message %s: %s", requestAddKey, requestAddValue)

		assert.Equal(t, 0, lo.CountBy(logs, byMsgContains(dummyUnexistentValue)), "does not contain message %q", dummyUnexistentValue)
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

func byMsgContains(msg string) cntPredicate[traceLogEntry] {
	return func(entry traceLogEntry) bool {
		return strings.Contains(entry.Msg, msg)
	}
}

func and[T any](predicates ...cntPredicate[T]) cntPredicate[T] {
	return func(entry T) bool {
		for _, pred := range predicates {
			if !pred(entry) {
				return false
			}
		}

		return true
	}
}
