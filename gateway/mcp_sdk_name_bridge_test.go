package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	restmcpadapter "github.com/TykTechnologies/tyk/internal/mcp/adapter"
)

func TestRequestForMCPAdapterSDKRequiresValidatedModernIngress(t *testing.T) {
	encoded := "=?base64?" + base64.StdEncoding.EncodeToString([]byte("日本語")) + "?="
	for _, test := range []struct {
		name       string
		version    string
		checked    bool
		wantCloned bool
	}{
		{name: "validated modern", version: mcp.ModernProtocolVersion, checked: true, wantCloned: true},
		{name: "unchecked modern", version: mcp.ModernProtocolVersion},
		{name: "validated legacy", version: mcp.LegacyFallbackProtocolVersion, checked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			r.Header.Set(mcp.HeaderName, encoded)
			ingress := mcp.NewProtocolContext(test.version, "", nil, nil)
			ingress.Validation.Checked = test.checked
			httpctx.SetMCPProtocolContext(r, ingress)

			got := requestForMCPAdapterSDK(r)
			require.Equal(t, encoded, r.Header.Get(mcp.HeaderName))
			if test.wantCloned {
				require.NotSame(t, r, got)
				require.Equal(t, "日本語", got.Header.Get(mcp.HeaderName))
				return
			}
			require.Same(t, r, got)
		})
	}
}

func TestRequestForMCPAdapterSDKExecutesEncodedToolName(t *testing.T) {
	const toolName = "日本語"
	var calls atomic.Int32
	adapter, err := restmcpadapter.NewSDKAdapter(restmcpadapter.SDKServerConfig{
		Name: "encoded-name-bridge",
		Tools: []oas.DerivedTool{{
			Name:        toolName,
			InputSchema: map[string]any{"type": "object"},
		}},
		CallTool: func(context.Context, *oas.DerivedTool, map[string]any) (*restmcpadapter.Recorder, error) {
			calls.Add(1)
			recorder := restmcpadapter.NewRecorder()
			recorder.Header().Set("Content-Type", "application/json")
			_, _ = recorder.Write([]byte(`{"ran":true}`))
			return recorder, nil
		},
	})
	require.NoError(t, err)

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": mcp.MethodToolsCall,
		"params": map[string]any{
			"name": toolName, "arguments": map[string]any{},
			"_meta": map[string]any{
				mcp.MetaKeyProtocolVersion:    mcp.ModernProtocolVersion,
				mcp.MetaKeyClientCapabilities: map[string]any{},
				mcp.MetaKeyClientInfo:         map[string]any{"name": "bridge-test", "version": "1"},
			},
		},
	})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set(mcp.HeaderProtocolVersion, mcp.ModernProtocolVersion)
	r.Header.Set(mcp.HeaderMethod, mcp.MethodToolsCall)
	r.Header.Set(mcp.HeaderName, "=?base64?"+base64.StdEncoding.EncodeToString([]byte(toolName))+"?=")
	var envelope mcp.RequestEnvelope
	require.NoError(t, json.Unmarshal(body, &envelope))
	ingress := mcp.NewProtocolContext(mcp.ModernProtocolVersion, "", &envelope, body)
	require.Nil(t, mcp.ValidateModernMirroredHeaders(r.Header, &envelope))
	ingress.Validation.Checked = true
	httpctx.SetMCPProtocolContext(r, ingress)

	rec := httptest.NewRecorder()
	handler := adapter.StreamableHTTPHandler(&mcpsdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	handler.ServeHTTP(rec, requestForMCPAdapterSDK(r))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.EqualValues(t, 1, calls.Load())
	require.Equal(t, "=?base64?5pel5pys6Kqe?=", r.Header.Get(mcp.HeaderName))
}
