package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProtocolContext(t *testing.T) {
	t.Parallel()

	envelope := func(method, params string) *RequestEnvelope {
		return &RequestEnvelope{JSONRPC: "2.0", Method: method, Params: json.RawMessage(params)}
	}
	tests := []struct {
		name       string
		header     string
		session    string
		envelope   *RequestEnvelope
		wantSource ProtocolVersionSource
		declared   string
		effective  string
		mismatch   bool
	}{
		{
			name: "matching header and metadata body", header: "2026-07-28",
			session:    "modern-must-ignore-session",
			envelope:   envelope("tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`),
			wantSource: ProtocolVersionSourceHeaderBody, declared: "2026-07-28", effective: "2026-07-28",
		},
		{
			name: "header only", header: "2025-11-25", envelope: envelope("tools/list", `{}`),
			wantSource: ProtocolVersionSourceHeader, declared: "2025-11-25", effective: "2025-11-25",
		},
		{
			name: "legacy initialize body", envelope: envelope("initialize", `{"protocolVersion":"2025-03-26"}`),
			wantSource: ProtocolVersionSourceBody, declared: "2025-03-26", effective: "2025-03-26",
		},
		{
			name: "session only", session: "session-id", envelope: envelope("tools/list", `{}`),
			wantSource: ProtocolVersionSourceSession, effective: LegacyFallbackProtocolVersion,
		},
		{
			name: "declaration free fallback", envelope: envelope("ping", `{}`),
			wantSource: ProtocolVersionSourceLegacyFallback, effective: LegacyFallbackProtocolVersion,
		},
		{
			name: "header body mismatch", header: "2026-07-28",
			envelope:   envelope("tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}`),
			wantSource: ProtocolVersionSourceHeaderBody, mismatch: true,
		},
		{
			name:       "two body declarations mismatch",
			envelope:   envelope("initialize", `{"protocolVersion":"2025-03-26","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
			wantSource: ProtocolVersionSourceBody, mismatch: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := NewProtocolContext(test.header, test.session, test.envelope, []byte("raw"))
			assert.Equal(t, test.wantSource, got.ProtocolVersionSource)
			assert.Equal(t, test.declared, got.DeclaredProtocolVersion)
			assert.Equal(t, test.effective, got.EffectiveProtocolVersion)
			assert.Equal(t, test.mismatch, got.DeclarationMismatch)
			assert.Equal(t, []byte("raw"), got.RawBody)
			if test.mismatch {
				require.NotEmpty(t, got.HeaderProtocolVersion+got.MetadataProtocolVersion+got.InitializeProtocolVersion)
			}
		})
	}
}

func TestRequestEnvelopeCachesParamsAndArguments(t *testing.T) {
	t.Parallel()

	envelope := &RequestEnvelope{Params: json.RawMessage(`{"name":"tool","arguments":{"ratio":1.25}}`)}
	assert.Equal(t, "tool", mustParamString(t, envelope, "name"))

	// Request envelopes are immutable after ingress. Replacing the raw bytes
	// proves subsequent consumers share the retained params parse.
	envelope.Params = json.RawMessage(`not-json`)
	arguments, err := envelope.Arguments()
	require.NoError(t, err)
	assert.Equal(t, json.Number("1.25"), arguments["ratio"])
	assert.Equal(t, "tool", mustParamString(t, envelope, "name"))
}

func mustParamString(t *testing.T, envelope *RequestEnvelope, name string) string {
	t.Helper()
	value, ok := envelope.ParamString(name)
	require.True(t, ok)
	return value
}
