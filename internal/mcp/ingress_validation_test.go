package mcp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func modernIngressContext(t *testing.T, method, params string) *ProtocolContext {
	t.Helper()
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(params), &payload))
	metadata, _ := payload["_meta"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
		payload["_meta"] = metadata
	}
	metadata[MetaKeyProtocolVersion] = ModernProtocolVersion
	metadata[MetaKeyClientCapabilities] = map[string]any{}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	return NewProtocolContext(ModernProtocolVersion, "ignored-modern-session", &RequestEnvelope{
		JSONRPC: "2.0", Method: method, Params: raw, ID: float64(1),
	}, nil)
}

func TestValidateProtocolDeclarations(t *testing.T) {
	t.Parallel()

	t.Run("modern metadata", func(t *testing.T) {
		ctx := modernIngressContext(t, MethodToolsList, `{}`)
		modern, ingressErr := ValidateProtocolDeclarations(ctx)
		assert.True(t, modern)
		assert.Nil(t, ingressErr)
		assert.Equal(t, ProtocolVersionSourceHeaderBody, ctx.ProtocolVersionSource)
		assert.True(t, ctx.IsModern(), "modern traffic must not be made stateful by a session header")
	})

	t.Run("missing capabilities", func(t *testing.T) {
		ctx := NewProtocolContext(ModernProtocolVersion, "", &RequestEnvelope{
			Method: MethodToolsList,
			Params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
		}, nil)
		modern, ingressErr := ValidateProtocolDeclarations(ctx)
		assert.True(t, modern)
		require.NotNil(t, ingressErr)
		assert.Equal(t, JSONRPCInvalidParams, ingressErr.Code)
	})

	t.Run("unsupported version", func(t *testing.T) {
		ctx := NewProtocolContext("2024-11-05", "", &RequestEnvelope{Method: MethodToolsList}, nil)
		_, ingressErr := ValidateProtocolDeclarations(ctx)
		require.NotNil(t, ingressErr)
		assert.Equal(t, CodeUnsupportedProtocolVersion, ingressErr.Code)
		assert.Equal(t, ServedProtocolVersions(), ingressErr.Data.(map[string]any)["supported"])
	})

	t.Run("required capability", func(t *testing.T) {
		ctx := modernIngressContext(t, MethodSamplingCreateMessage, `{}`)
		_, ingressErr := ValidateProtocolDeclarations(ctx)
		require.NotNil(t, ingressErr)
		assert.Equal(t, CodeMissingRequiredClientCapabilities, ingressErr.Code)
	})

	t.Run("headerless legacy continuity", func(t *testing.T) {
		ctx := NewProtocolContext("", "", &RequestEnvelope{Method: MethodInitialize, Params: json.RawMessage(`{"protocolVersion":"2025-03-26"}`)}, nil)
		modern, ingressErr := ValidateProtocolDeclarations(ctx)
		assert.False(t, modern)
		assert.Nil(t, ingressErr)
	})
}

func TestValidateModernMirroredHeaders(t *testing.T) {
	t.Parallel()
	envelope := &RequestEnvelope{Method: MethodToolsCall, Params: json.RawMessage(`{"name":"café","arguments":{}}`)}
	header := make(http.Header)
	header.Set(HeaderMethod, MethodToolsCall)
	header.Set(HeaderName, "=?base64?"+base64.StdEncoding.EncodeToString([]byte("café"))+"?=")
	header.Set(HeaderParamPrefix+"Count", "7")
	assert.Nil(t, ValidateModernMirroredHeaders(header, envelope))

	header.Set(HeaderName, "other")
	assert.Equal(t, CodeHeaderMismatch, ValidateModernMirroredHeaders(header, envelope).Code)
	header.Set(HeaderName, "=?base64?broken?=")
	assert.Equal(t, CodeHeaderMismatch, ValidateModernMirroredHeaders(header, envelope).Code)

	header.Set(HeaderName, "=?base64?"+base64.StdEncoding.EncodeToString([]byte("café"))+"?=")
	header.Del(HeaderMethod)
	assert.Equal(t, CodeHeaderMismatch, ValidateModernMirroredHeaders(header, envelope).Code)
	header.Set(HeaderMethod, MethodPromptsGet)
	ingressErr := ValidateModernMirroredHeaders(header, envelope)
	assert.Equal(t, CodeHeaderMismatch, ingressErr.Code)
	assert.NotContains(t, ingressErr.Message, MethodPromptsGet)
	assert.NotContains(t, ingressErr.Message, MethodToolsCall)
	header.Set(HeaderMethod, MethodToolsCall)
	header[HeaderParamPrefix+"Count"] = []string{"7", "8"}
	assert.Equal(t, CodeHeaderMismatch, ValidateModernMirroredHeaders(header, envelope).Code)
	header.Set(HeaderParamPrefix+"bad name", "7")
	assert.Equal(t, CodeHeaderMismatch, ValidateModernMirroredHeaders(header, envelope).Code)
}

func TestDecodeMirroredHeader(t *testing.T) {
	t.Parallel()
	decoded, ok := DecodeMirroredHeader("plain")
	assert.True(t, ok)
	assert.Equal(t, "plain", decoded)
	decoded, ok = DecodeMirroredHeader("=?base64?" + base64.StdEncoding.EncodeToString([]byte("café")) + "?=")
	assert.True(t, ok)
	assert.Equal(t, "café", decoded)
	_, ok = DecodeMirroredHeader("=?base64?broken")
	assert.False(t, ok)
}

func TestServedProtocolVersions(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"}, ServedProtocolVersions())
	assert.False(t, IsServedProtocolVersion("2024-11-05"))
}
