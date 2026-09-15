package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
)

const (
	// HeaderProtocolVersion carries the MCP protocol version on Streamable HTTP.
	HeaderProtocolVersion = "Mcp-Protocol-Version"
	// HeaderSessionID carries the stateful MCP session identifier.
	HeaderSessionID = "Mcp-Session-Id"
	// MetaKeyProtocolVersion is the modern namespaced metadata declaration.
	MetaKeyProtocolVersion = "io.modelcontextprotocol/protocolVersion"
	// LegacyFallbackProtocolVersion is the effective version for established
	// sessions and declaration-free legacy requests.
	LegacyFallbackProtocolVersion = "2025-03-26"
	ModernProtocolVersion         = "2026-07-28"
)

// ProtocolVersionSource describes how the effective MCP version was detected.
type ProtocolVersionSource string

const (
	ProtocolVersionSourceHeaderBody     ProtocolVersionSource = "header_body"
	ProtocolVersionSourceHeader         ProtocolVersionSource = "header"
	ProtocolVersionSourceBody           ProtocolVersionSource = "body"
	ProtocolVersionSourceSession        ProtocolVersionSource = "session"
	ProtocolVersionSourceLegacyFallback ProtocolVersionSource = "legacy_fallback"
)

// RequestEnvelope is the single parsed JSON-RPC request retained for routing,
// policy, error handling, filtering, handler selection, and analytics.
type RequestEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

// ProtocolValidation retains the final ingress outcome for telemetry.
type ProtocolValidation struct {
	HTTPStatus int
	Checked    bool
	Code       int
	Message    string
}

// UnmarshalJSON preserves numeric identifiers without float64 rounding.
func (r *RequestEnvelope) UnmarshalJSON(data []byte) error {
	type request RequestEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode((*request)(r))
}

// ProtocolContext contains raw protocol declarations and their normalized
// agreement. Rejected declarations remain available; conflicts leave the
// effective version empty. The declared version prefers the explicit header.
type ProtocolContext struct {
	Validation ProtocolValidation
	Envelope   *RequestEnvelope
	RawBody    []byte

	HeaderProtocolVersion     string
	MetadataProtocolVersion   string
	InitializeProtocolVersion string
	BodyProtocolVersionRaw    json.RawMessage
	HasSession                bool
	DeclarationMismatch       bool

	DeclaredProtocolVersion  string
	EffectiveProtocolVersion string
	ProtocolVersionSource    ProtocolVersionSource
}

// NewProtocolContext normalizes declarations from one already-parsed envelope.
func NewProtocolContext(headerVersion, sessionID string, envelope *RequestEnvelope, rawBody []byte) *ProtocolContext {
	ctx := &ProtocolContext{
		Envelope:              envelope,
		RawBody:               append([]byte(nil), rawBody...),
		HeaderProtocolVersion: headerVersion,
		HasSession:            strings.TrimSpace(sessionID) != "",
	}

	bodyVersion, bodyDeclared, bodyMismatch := ctx.extractBodyProtocolVersion()
	headerDeclared := ctx.HeaderProtocolVersion != ""

	if headerDeclared {
		ctx.DeclaredProtocolVersion = ctx.HeaderProtocolVersion
	} else if bodyDeclared {
		ctx.DeclaredProtocolVersion = bodyVersion
		if bodyVersion == "" {
			ctx.DeclaredProtocolVersion = string(ctx.BodyProtocolVersionRaw)
		}
	}
	switch {
	case headerDeclared && bodyDeclared:
		ctx.ProtocolVersionSource = ProtocolVersionSourceHeaderBody
		if bodyMismatch || ctx.HeaderProtocolVersion != bodyVersion {
			ctx.DeclarationMismatch = true
			return ctx
		}
		ctx.DeclaredProtocolVersion = bodyVersion
		ctx.EffectiveProtocolVersion = bodyVersion
	case headerDeclared:
		ctx.ProtocolVersionSource = ProtocolVersionSourceHeader
		ctx.DeclaredProtocolVersion = ctx.HeaderProtocolVersion
		ctx.EffectiveProtocolVersion = ctx.HeaderProtocolVersion
	case bodyDeclared:
		ctx.ProtocolVersionSource = ProtocolVersionSourceBody
		if bodyMismatch {
			ctx.DeclarationMismatch = true
			return ctx
		}
		ctx.DeclaredProtocolVersion = bodyVersion
		ctx.EffectiveProtocolVersion = bodyVersion
	default:
		ctx.ProtocolVersionSource = ProtocolVersionSourceLegacyFallback
		ctx.EffectiveProtocolVersion = LegacyFallbackProtocolVersion
	}

	return ctx
}

func (c *ProtocolContext) extractBodyProtocolVersion() (version string, declared, mismatch bool) {
	if c.Envelope == nil || len(c.Envelope.Params) == 0 {
		return "", false, false
	}

	var params map[string]json.RawMessage
	if json.Unmarshal(c.Envelope.Params, &params) != nil {
		return "", false, false
	}
	if raw, ok := params["protocolVersion"]; ok && c.Envelope.Method == MethodInitialize {
		c.BodyProtocolVersionRaw = append([]byte(nil), raw...)
		declared = true
		if json.Unmarshal(raw, &c.InitializeProtocolVersion) != nil || c.InitializeProtocolVersion == "" {
			mismatch = true
		}
	}

	if rawMeta, ok := params["_meta"]; ok {
		var metadata map[string]json.RawMessage
		if json.Unmarshal(rawMeta, &metadata) == nil {
			if raw, exists := metadata[MetaKeyProtocolVersion]; exists {
				c.BodyProtocolVersionRaw = append([]byte(nil), raw...)
				declared = true
				if json.Unmarshal(raw, &c.MetadataProtocolVersion) != nil || c.MetadataProtocolVersion == "" {
					mismatch = true
				}
			}
		}
	}

	switch {
	case c.InitializeProtocolVersion != "" && c.MetadataProtocolVersion != "":
		return c.MetadataProtocolVersion, true, mismatch || c.InitializeProtocolVersion != c.MetadataProtocolVersion
	case c.MetadataProtocolVersion != "":
		return c.MetadataProtocolVersion, true, mismatch
	case c.InitializeProtocolVersion != "":
		return c.InitializeProtocolVersion, true, mismatch
	default:
		return "", declared, mismatch
	}
}

// IsModern reports an unambiguous modern protocol selection.
func (c *ProtocolContext) IsModern() bool {
	return c != nil && !c.DeclarationMismatch && c.EffectiveProtocolVersion == ModernProtocolVersion
}
