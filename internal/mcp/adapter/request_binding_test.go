package adapter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type bindingMarker struct{}

func TestSDKRequestBindingCurrentMessageAndSessionOwner(t *testing.T) {
	var calls atomic.Int64
	a, err := NewSDKAdapter(SDKServerConfig{Name: "binding", RequireRequestBinding: true,
		Tools: []oas.DerivedTool{{Name: "current", InputSchema: map[string]any{"type": "object"}}},
		CallTool: func(ctx context.Context, _ *oas.DerivedTool, _ map[string]any) (*Recorder, error) {
			current, ok := CurrentRequestContext(ctx)
			if !ok {
				return nil, fmt.Errorf("missing current binding")
			}
			calls.Add(1)
			rec := NewRecorder()
			_, err := rec.Write([]byte(current.Value(bindingMarker{}).(string)))
			return rec, err
		},
	})
	require.NoError(t, err)
	serve := func(method, body, sid, owner, marker string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://localhost/mcp", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Authorization", "original "+marker)
		if sid != "" {
			r.Header.Set("Mcp-Session-Id", sid)
		}
		if owner != "" {
			r = r.WithContext(WithRequestBinding(r.Context(), context.WithValue(r.Context(), bindingMarker{}, marker), owner))
		}
		rec := httptest.NewRecorder()
		a.StreamableHTTPHandler(nil).ServeHTTP(rec, r)
		assert.Equal(t, "original "+marker, r.Header.Get("Authorization"))
		return rec
	}
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"current","arguments":{}}}`
	initialized := serve("POST", init, "", "owner-a", "initialization")
	require.Equal(t, 200, initialized.Code, initialized.Body.String())
	sid := initialized.Header().Get("Mcp-Session-Id")
	require.NotEmpty(t, sid)
	require.Equal(t, 403, serve("POST", init, "", "", "unverified").Code)
	for _, method := range []string{"POST", "GET", "DELETE"} {
		denied := serve(method, call, sid, "owner-b", "foreign")
		require.Equal(t, 403, denied.Code, denied.Body.String())
	}
	require.Zero(t, calls.Load())
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			marker := fmt.Sprintf("current-%d", i)
			body := strings.Replace(call, `"id":2`, fmt.Sprintf(`"id":%d`, i+10), 1)
			response := serve("POST", body, sid, "owner-a", marker)
			assert.Equal(t, 200, response.Code, response.Body.String())
			assert.Contains(t, response.Body.String(), marker)
			assert.NotContains(t, response.Body.String(), "initialization")
		}(i)
	}
	wg.Wait()
	require.EqualValues(t, 16, calls.Load())
}

func TestSDKRequestBindingRestoresHeadersAndRejectsForgedMetadata(t *testing.T) {
	for _, authorization := range [][]string{nil, {}, {"first", "second"}} {
		r := httptest.NewRequest("POST", "http://localhost/mcp", nil)
		if authorization != nil {
			r.Header["Authorization"] = authorization
		}
		r.Header.Set("X-Tyk-Mcp-Request-Binding", "forged")
		called := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, got *http.Request) {
			called = true
			assert.Equal(t, r.Header, got.Header)
			got.Header.Set("X-New", "value")
		})
		denied := httptest.NewRecorder()
		withSDKRequestBinding(next).ServeHTTP(denied, r)
		require.Equal(t, 403, denied.Code)
		require.False(t, called)
		r = r.WithContext(WithRequestBinding(r.Context(), r.Context(), "verified-owner"))
		withSDKRequestBinding(next).ServeHTTP(httptest.NewRecorder(), r)
		require.True(t, called)
		require.Empty(t, r.Header.Get("X-New"))
	}
}
