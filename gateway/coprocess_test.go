package gateway

import (
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestRebuildResponseHeaders(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	h := CustomMiddlewareResponseHook{
		mw: nil,
		Gw: ts.Gw,
	}

	persistedHeaderKey := "persisted-header"
	removedHeaderKey := "removed-header"
	testCases := []struct {
		name                               string
		initialResponseHeaders             map[string]string
		responseHeadersFromCoprocessPlugin map[string]string
		expectedFinalResponseHeaders       map[string]string
	}{
		{
			name: "header removed by coprocess plugin",
			initialResponseHeaders: map[string]string{
				persistedHeaderKey: "1",
				removedHeaderKey:   "1",
			},
			responseHeadersFromCoprocessPlugin: map[string]string{
				persistedHeaderKey: "1",
			},
			expectedFinalResponseHeaders: map[string]string{
				persistedHeaderKey: "1",
			},
		},
		{
			name: "headers are not modified in coprocess plugin",
			initialResponseHeaders: map[string]string{
				persistedHeaderKey: "1",
			},
			responseHeadersFromCoprocessPlugin: map[string]string{
				persistedHeaderKey: "1",
			},
			expectedFinalResponseHeaders: map[string]string{
				persistedHeaderKey: "1",
			},
		},
		{
			name: "a header is added by the coprocess plugin",
			initialResponseHeaders: map[string]string{
				persistedHeaderKey: "1",
			},
			responseHeadersFromCoprocessPlugin: map[string]string{
				persistedHeaderKey: "1",
				"new-added-header": "1",
			},
			expectedFinalResponseHeaders: map[string]string{
				persistedHeaderKey: "1",
				"new-added-header": "1",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			upstreamRes := http.Response{Header: http.Header{}}

			// build the initial object
			for headerName, headerValue := range tc.initialResponseHeaders {
				upstreamRes.Header.Add(headerName, headerValue)
			}

			ret := coprocess.Object{
				Response: &coprocess.ResponseObject{},
			}
			ret.Response.Headers = tc.responseHeadersFromCoprocessPlugin

			h.RebuildResponseHeaders(&upstreamRes, &ret)

			assert.Equal(t, len(tc.expectedFinalResponseHeaders), len(upstreamRes.Header))

			for headerName, expectedHeaderValue := range tc.expectedFinalResponseHeaders {
				currentHeaderValue := upstreamRes.Header.Get(headerName)
				assert.Equal(t, expectedHeaderValue, currentHeaderValue)
			}
		})
	}
}
