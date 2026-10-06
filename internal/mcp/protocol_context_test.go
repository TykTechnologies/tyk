package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestEnvelopeUnmarshalJSONStrictOwnedFields(t *testing.T) {
	t.Parallel()

	valid := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"tool","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"sampling":{}}},"arguments":{"name":1,"Name":2,"name":3}},"id":9007199254740993}`
	var envelope RequestEnvelope
	require.NoError(t, json.Unmarshal([]byte(valid), &envelope))
	require.Equal(t, json.Number("9007199254740993"), envelope.ID)
	require.JSONEq(t, `{"name":"tool","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"sampling":{}}},"arguments":{"name":1,"Name":2,"name":3}}`, string(envelope.Params))

	tests := []struct {
		name string
		body string
	}{
		{"duplicate jsonrpc", `{"jsonrpc":"2.0","jsonrpc":"2.0","method":"tools/list"}`},
		{"noncanonical jsonrpc", `{"JsonRpc":"2.0","method":"tools/list"}`},
		{"duplicate method", `{"jsonrpc":"2.0","method":"tools/list","method":"tools/call"}`},
		{"noncanonical method", `{"jsonrpc":"2.0","Method":"tools/list"}`},
		{"duplicate params", `{"jsonrpc":"2.0","method":"tools/list","params":{},"params":{}}`},
		{"noncanonical params", `{"jsonrpc":"2.0","method":"tools/list","Params":{}}`},
		{"duplicate id", `{"jsonrpc":"2.0","method":"tools/list","id":1,"id":2}`},
		{"noncanonical id", `{"jsonrpc":"2.0","method":"tools/list","ID":1}`},
		{"duplicate protocol version", `{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2026-07-28","protocolVersion":"2025-03-26"}}`},
		{"noncanonical protocol version", `{"jsonrpc":"2.0","method":"initialize","params":{"ProtocolVersion":"2026-07-28"}}`},
		{"duplicate meta", `{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{},"_meta":{}}}`},
		{"noncanonical meta", `{"jsonrpc":"2.0","method":"tools/list","params":{"_Meta":{}}}`},
		{"duplicate name", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"one","name":"two"}}`},
		{"noncanonical name", `{"jsonrpc":"2.0","method":"tools/call","params":{"Name":"tool"}}`},
		{"duplicate uri", `{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"one","uri":"two"}}`},
		{"noncanonical uri", `{"jsonrpc":"2.0","method":"resources/read","params":{"URI":"resource"}}`},
		{"duplicate metadata protocol", `{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`},
		{"noncanonical metadata protocol", `{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/ProtocolVersion":"2026-07-28"}}}`},
		{"duplicate client capabilities", `{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientCapabilities":{}}}}`},
		{"noncanonical client capabilities", `{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/ClientCapabilities":{}}}}`},
		{"duplicate client info", `{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/clientInfo":{},"io.modelcontextprotocol/clientInfo":{}}}}`},
		{"noncanonical client info", `{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/ClientInfo":{}}}}`},
		{"duplicate inspected capability", `{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{"sampling":{},"sampling":{}}}}}`},
		{"noncanonical inspected capability", `{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{"Sampling":{}}}}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got RequestEnvelope
			require.Error(t, json.Unmarshal([]byte(test.body), &got))
		})
	}
}

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
			envelope:   envelope("tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
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
			wantSource: ProtocolVersionSourceLegacyFallback, effective: LegacyFallbackProtocolVersion,
		},
		{
			name: "declaration free fallback", envelope: envelope("ping", `{}`),
			wantSource: ProtocolVersionSourceLegacyFallback, effective: LegacyFallbackProtocolVersion,
		},
		{
			name: "header body mismatch", header: "2026-07-28",
			envelope:   envelope("tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}`),
			wantSource: ProtocolVersionSourceHeaderBody, declared: "2026-07-28", mismatch: true,
		},
		{
			name:       "two body declarations mismatch",
			envelope:   envelope("initialize", `{"protocolVersion":"2025-03-26","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
			wantSource: ProtocolVersionSourceBody, declared: "2026-07-28", mismatch: true,
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
