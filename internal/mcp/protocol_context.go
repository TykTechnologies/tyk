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
	// MetaKeyProtocolVersion is the v1.7 namespaced metadata declaration.
	MetaKeyProtocolVersion = "io.modelcontextprotocol/protocolVersion"
	// LegacyFallbackProtocolVersion is the effective version for established
	// sessions and declaration-free legacy requests.
	LegacyFallbackProtocolVersion = "2025-03-26"
	// ModernProtocolVersion selects the GA stateless protocol behavior.
	ModernProtocolVersion = "2026-07-28"
)

// servedProtocolVersions is ordered newest to oldest and is shared by ingress,
// handler selection, and server discovery.
var servedProtocolVersions = []string{
	ModernProtocolVersion,
	"2025-11-25",
	"2025-06-18",
	LegacyFallbackProtocolVersion,
}

// ServedProtocolVersions returns a copy of the ordered version registry.
func ServedProtocolVersions() []string {
	return append([]string(nil), servedProtocolVersions...)
}

// IsServedProtocolVersion reports whether Gateway can actually route a version.
func IsServedProtocolVersion(version string) bool {
	for _, served := range servedProtocolVersions {
		if version == served {
			return true
		}
	}
	return false
}

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

	paramsObject    map[string]json.RawMessage
	paramsErr       error
	paramsParsed    bool
	arguments       map[string]any
	argumentsErr    error
	argumentsParsed bool
}

// ParamsObject returns the request params decoded once as raw fields. The
// retained map lets ingress metadata and mirrored-header validation share the
// bounded request parse without repeatedly deserializing the whole object.
func (e *RequestEnvelope) ParamsObject() (map[string]json.RawMessage, error) {
	if e == nil {
		return nil, nil
	}
	if !e.paramsParsed {
		e.paramsParsed = true
		e.paramsErr = json.Unmarshal(e.Params, &e.paramsObject)
	}
	return e.paramsObject, e.paramsErr
}

// ParamString returns one string-valued parameter from the cached params.
func (e *RequestEnvelope) ParamString(name string) (string, bool) {
	params, err := e.ParamsObject()
	if err != nil {
		return "", false
	}
	var value string
	if json.Unmarshal(params[name], &value) != nil {
		return "", false
	}
	return value, true
}

// Arguments returns tools/call arguments decoded once with json.Number
// preservation for schema-aware mirrored-header comparison.
func (e *RequestEnvelope) Arguments() (map[string]any, error) {
	if e == nil {
		return nil, nil
	}
	if !e.argumentsParsed {
		e.argumentsParsed = true
		params, err := e.ParamsObject()
		if err != nil {
			e.argumentsErr = err
			return nil, err
		}
		rawArguments, present := params["arguments"]
		if !present {
			return nil, nil
		}
		decoder := json.NewDecoder(bytes.NewReader(rawArguments))
		decoder.UseNumber()
		e.argumentsErr = decoder.Decode(&e.arguments)
	}
	return e.arguments, e.argumentsErr
}

// IsModern reports whether the normalized context unambiguously selected the
// GA modern protocol.
func (c *ProtocolContext) IsModern() bool {
	return c != nil && !c.DeclarationMismatch && c.EffectiveProtocolVersion == ModernProtocolVersion
}

// ProtocolContext contains raw protocol declarations and their normalized
// agreement. Raw declarations remain available when they conflict, while the
// declared and effective versions are deliberately empty.
type ProtocolContext struct {
	Envelope *RequestEnvelope
	RawBody  []byte

	HeaderProtocolVersion     string
	MetadataProtocolVersion   string
	InitializeProtocolVersion string
	BodyProtocolVersionRaw    json.RawMessage
	Metadata                  map[string]json.RawMessage
	ClientCapabilities        json.RawMessage
	ClientInfo                json.RawMessage
	MetadataProtocolPresent   bool
	MetadataProtocolValid     bool
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
		HeaderProtocolVersion: strings.TrimSpace(headerVersion),
		HasSession:            strings.TrimSpace(sessionID) != "",
	}

	bodyVersion, bodyDeclared, bodyMismatch := ctx.extractBodyProtocolVersion()
	headerDeclared := ctx.HeaderProtocolVersion != ""

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
	case ctx.HasSession:
		ctx.ProtocolVersionSource = ProtocolVersionSourceSession
		ctx.EffectiveProtocolVersion = LegacyFallbackProtocolVersion
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

	params, err := c.Envelope.ParamsObject()
	if err != nil {
		return "", false, false
	}
	if raw, ok := params["protocolVersion"]; ok {
		c.BodyProtocolVersionRaw = append([]byte(nil), raw...)
		declared = true
		if json.Unmarshal(raw, &c.InitializeProtocolVersion) != nil || c.InitializeProtocolVersion == "" {
			mismatch = true
		}
	}

	if rawMeta, ok := params["_meta"]; ok {
		var metadata map[string]json.RawMessage
		if json.Unmarshal(rawMeta, &metadata) == nil {
			c.Metadata = metadata
			c.ClientCapabilities = append([]byte(nil), metadata["io.modelcontextprotocol/clientCapabilities"]...)
			c.ClientInfo = append([]byte(nil), metadata["io.modelcontextprotocol/clientInfo"]...)
			if raw, exists := metadata[MetaKeyProtocolVersion]; exists {
				c.MetadataProtocolPresent = true
				c.BodyProtocolVersionRaw = append([]byte(nil), raw...)
				declared = true
				if json.Unmarshal(raw, &c.MetadataProtocolVersion) != nil || c.MetadataProtocolVersion == "" {
					mismatch = true
				} else {
					c.MetadataProtocolValid = true
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
