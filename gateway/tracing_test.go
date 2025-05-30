package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TykTechnologies/kin-openapi/openapi3"
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

func TestTraceHandler_RateLimiterExceeded(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create OAS definition with strict rate limit (1 request per minute)
	// todo: extract to OAS builder
	oasDef := oas.OAS{}
	oasDef.Paths = openapi3.Paths{
		"/uuid": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "uuidget",
				Description: "uuidget descr",
			},
		},
	}
	oasDef.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Strip: true,
				Value: "/rate-limited-api/",
			},
		},
		Upstream: oas.Upstream{
			Proxy: &oas.Proxy{Enabled: true},
			URL:   "http://localhost:3128/",
			// todo: split api rate limit tests and endpoint rate limits
			// add edd endpoint with middlewares and
			RateLimit: &oas.RateLimit{
				Enabled: false,
				Rate:    10,
				Per:     oas.ReadableDuration(60 * time.Second),
			},
		},
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"uuidget": {
					RateLimit: &oas.RateLimitEndpoint{
						Enabled: true,
						Rate:    1,
						Per:     oas.ReadableDuration(60 * time.Second),
					},
				},
			},
		},
	})

	// Create trace request
	traceReq := traceRequest{
		Request: &traceHttpRequest{
			Method: http.MethodGet,
			Path:   "/uuid",
		},
		OAS: &oasDef,
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
	req2 = ts.withAuth(req2)

	w2 := httptest.NewRecorder()
	ts.Gw.traceHandler(w2, req2)

	// Parse response
	var traceResp2 traceResponse
	err = json.Unmarshal(w2.Body.Bytes(), &traceResp2)
	assert.NoError(t, err)

	// Verify rate limit response
	assert.Contains(t, traceResp2.Response, "429 Too Many Requests")
	assert.Contains(t, traceResp2.Logs, "API Rate Limit Exceeded")
}
