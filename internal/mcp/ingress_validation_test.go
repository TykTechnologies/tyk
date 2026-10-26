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

	t.Run("upstream-owned capability requirements", func(t *testing.T) {
		ctx := modernIngressContext(t, "sampling/createMessage", `{}`)
		_, ingressErr := ValidateProtocolDeclarations(ctx)
		require.Nil(t, ingressErr)
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
}

func TestDecodeMirroredHeader(t *testing.T) {
	t.Parallel()
	decoded, ok := DecodeMirroredHeader("plain")
	assert.True(t, ok)
	assert.Equal(t, "plain", decoded)
	_, ok = DecodeMirroredHeader("=?base64?broken")
	assert.False(t, ok)
}

func TestServedProtocolVersions(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"}, ServedProtocolVersions())
	assert.False(t, IsServedProtocolVersion("2024-11-05"))
}

type legacyEndpoint struct{}

func (legacyEndpoint) SupportedProtocolVersions() []string { return LegacyProtocolVersions() }

func TestMCPIngressEndpointAndHeaderContracts(t *testing.T) {
	t.Run("synthetic modern unsupported", func(t *testing.T) {
		ctx := modernIngressContext(t, "tools/list", `{}`)
		_, err := ValidateProtocolDeclarations(ctx, legacyEndpoint{})
		require.NotNil(t, err)
		require.Equal(t, CodeUnsupportedProtocolVersion, err.Code)
		require.Equal(t, LegacyProtocolVersions(), err.Data.(map[string]any)["supported"])
	})
	t.Run("legacy initialize negotiation", func(t *testing.T) {
		ctx := NewProtocolContext("", "", &RequestEnvelope{Method: MethodInitialize, Params: json.RawMessage(`{"protocolVersion":"2099-01-01"}`)}, nil)
		modern, err := ValidateProtocolDeclarations(ctx, legacyEndpoint{})
		require.False(t, modern)
		require.Nil(t, err)
	})
	for _, values := range [][]string{{""}, {"2026-07-28", "2026-07-28"}, {"2026-07-28,2026-07-28"}, {"2026-7-28"}, {" 2026-07-28"}} {
		require.NotNil(t, ValidateProtocolHeader(http.Header{HeaderProtocolVersion: values}), values)
	}
	for _, method := range []string{"initialize", "ping", "notifications/initialized", "notifications/roots/list_changed", "logging/setLevel", "resources/subscribe", "resources/unsubscribe"} {
		_, err := ValidateProtocolDeclarations(modernIngressContext(t, method, `{}`))
		require.NotNil(t, err, method)
		require.Equal(t, JSONRPCMethodNotFound, err.Code)
	}
	envelope := &RequestEnvelope{Method: MethodToolsCall, Params: json.RawMessage(`{"name":"tool"}`)}
	headers := http.Header{HeaderMethod: {MethodToolsCall}, HeaderName: {"tool"}}
	headers[HeaderMethod] = []string{MethodToolsCall, MethodToolsCall}
	require.NotNil(t, ValidateModernMirroredHeaders(headers, envelope))
	headers[HeaderMethod] = []string{MethodToolsCall}
	headers["Mcp-Param-Unrecognized"] = []string{"=?base64?unknown-custom-encoding", "second"}
	require.Nil(t, ValidateModernMirroredHeaders(headers, envelope), "unknown bindings belong to the upstream")
}

func TestModernIngressRejectsInvalidMetadataShapes(t *testing.T) {
	t.Parallel()
	const version = `"2026-07-28"`
	tests := []struct {
		name   string
		params string
	}{
		{"null params", `null`},
		{"null metadata", `{"_meta":null}`},
		{"array metadata", `{"_meta":[]}`},
		{"scalar metadata", `{"_meta":1}`},
		{"null capabilities", `{"_meta":{"io.modelcontextprotocol/protocolVersion":` + version + `,"io.modelcontextprotocol/clientCapabilities":null}}`},
		{"array capabilities", `{"_meta":{"io.modelcontextprotocol/protocolVersion":` + version + `,"io.modelcontextprotocol/clientCapabilities":[]}}`},
		{"scalar capabilities", `{"_meta":{"io.modelcontextprotocol/protocolVersion":` + version + `,"io.modelcontextprotocol/clientCapabilities":true}}`},
		{"null nested capability", `{"_meta":{"io.modelcontextprotocol/protocolVersion":` + version + `,"io.modelcontextprotocol/clientCapabilities":{"sampling":null}}}`},
		{"array nested capability", `{"_meta":{"io.modelcontextprotocol/protocolVersion":` + version + `,"io.modelcontextprotocol/clientCapabilities":{"roots":[]}}}`},
		{"scalar nested capability", `{"_meta":{"io.modelcontextprotocol/protocolVersion":` + version + `,"io.modelcontextprotocol/clientCapabilities":{"tasks":1}}}`},
		{"null client info", `{"_meta":{"io.modelcontextprotocol/protocolVersion":` + version + `,"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":null}}`},
		{"array client info", `{"_meta":{"io.modelcontextprotocol/protocolVersion":` + version + `,"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":[]}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var params json.RawMessage = []byte(test.params)
			ctx := NewProtocolContext(ModernProtocolVersion, "", &RequestEnvelope{Method: MethodToolsList, Params: params}, nil)
			modern, ingressErr := ValidateProtocolDeclarations(ctx)
			require.True(t, modern)
			require.NotNil(t, ingressErr)
			require.Equal(t, JSONRPCInvalidParams, ingressErr.Code)
		})
	}
}

func TestModernIngressRequiresMatchingVersionDeclarations(t *testing.T) {
	t.Parallel()
	validMeta := func(version string) json.RawMessage {
		return json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + version + `","io.modelcontextprotocol/clientCapabilities":{}}}`)
	}
	tests := []struct {
		name       string
		header     string
		params     json.RawMessage
		wantCode   int
		wantModern bool
	}{
		{"missing header", "", validMeta(ModernProtocolVersion), CodeHeaderMismatch, true},
		{"mismatched header", ModernProtocolVersion, validMeta("2025-11-25"), CodeHeaderMismatch, true},
		{"unknown matching version", "2099-01-01", validMeta("2099-01-01"), CodeUnsupportedProtocolVersion, false},
		{"unknown header with modern body", "2099-01-01", validMeta(ModernProtocolVersion), CodeHeaderMismatch, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := NewProtocolContext(test.header, "", &RequestEnvelope{Method: MethodToolsList, Params: test.params}, nil)
			modern, ingressErr := ValidateProtocolDeclarations(ctx)
			require.Equal(t, test.wantModern, modern)
			require.NotNil(t, ingressErr)
			require.Equal(t, test.wantCode, ingressErr.Code)
			if test.wantCode == CodeUnsupportedProtocolVersion {
				data := ingressErr.Data.(map[string]any)
				require.Equal(t, ServedProtocolVersions(), data["supported"])
			}
		})
	}
}

func TestProtocolHeaderRejectsCaseVariantAndCombinedMultiplicity(t *testing.T) {
	t.Parallel()
	for _, header := range []http.Header{
		{HeaderProtocolVersion: {ModernProtocolVersion}, "mcp-protocol-version": {ModernProtocolVersion}},
		{HeaderProtocolVersion: {ModernProtocolVersion + "," + ModernProtocolVersion}},
	} {
		err := ValidateProtocolHeader(header)
		require.NotNil(t, err)
		require.Equal(t, CodeHeaderMismatch, err.Code)
	}
}

func TestModernMirroredHeaderMultiplicityAndEncoding(t *testing.T) {
	t.Parallel()
	envelope := &RequestEnvelope{Method: MethodToolsCall, Params: json.RawMessage(`{"name":"café"}`)}
	encodedName := "=?base64?" + base64.StdEncoding.EncodeToString([]byte("café")) + "?="
	valid := http.Header{HeaderMethod: {MethodToolsCall}, HeaderName: {encodedName}}
	require.Nil(t, ValidateModernMirroredHeaders(valid, envelope))

	tests := []struct {
		name   string
		header http.Header
	}{
		{"missing method", http.Header{HeaderName: {encodedName}}},
		{"duplicate method", http.Header{HeaderMethod: {MethodToolsCall, MethodToolsCall}, HeaderName: {encodedName}}},
		{"case variant duplicate method", http.Header{HeaderMethod: {MethodToolsCall}, "mcp-method": {MethodToolsCall}, HeaderName: {encodedName}}},
		{"comma combined method", http.Header{HeaderMethod: {MethodToolsCall + "," + MethodToolsCall}, HeaderName: {encodedName}}},
		{"mismatched method", http.Header{HeaderMethod: {MethodToolsList}, HeaderName: {encodedName}}},
		{"missing name", http.Header{HeaderMethod: {MethodToolsCall}}},
		{"duplicate name", http.Header{HeaderMethod: {MethodToolsCall}, HeaderName: {encodedName, encodedName}}},
		{"case variant duplicate name", http.Header{HeaderMethod: {MethodToolsCall}, HeaderName: {encodedName}, "mcp-name": {encodedName}}},
		{"partial wrapper", http.Header{HeaderMethod: {MethodToolsCall}, HeaderName: {"=?base64?Y2Fmw6k="}}},
		{"invalid base64", http.Header{HeaderMethod: {MethodToolsCall}, HeaderName: {"=?base64?broken?="}}},
		{"invalid decoded utf8", http.Header{HeaderMethod: {MethodToolsCall}, HeaderName: {"=?base64?/w==?="}}},
		{"raw unicode", http.Header{HeaderMethod: {MethodToolsCall}, HeaderName: {"café"}}},
		{"raw control", http.Header{HeaderMethod: {MethodToolsCall}, HeaderName: {"cafe\n"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateModernMirroredHeaders(test.header, envelope)
			require.NotNil(t, err)
			require.Equal(t, CodeHeaderMismatch, err.Code)
		})
	}
}

func TestModernMirroredHeaderRejectsInvalidPrimitiveNameShapes(t *testing.T) {
	t.Parallel()
	for _, params := range []string{`null`, `{}`, `{"name":null}`, `{"name":1}`, `{"name":[]}`} {
		envelope := &RequestEnvelope{Method: MethodToolsCall, Params: json.RawMessage(params)}
		headers := http.Header{HeaderMethod: {MethodToolsCall}, HeaderName: {"tool"}}
		err := ValidateModernMirroredHeaders(headers, envelope)
		require.NotNil(t, err, params)
		require.Equal(t, CodeHeaderMismatch, err.Code, params)
	}
}
