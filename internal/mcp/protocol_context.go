package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	// HeaderProtocolVersion carries the MCP protocol version on Streamable HTTP.
	HeaderProtocolVersion = "Mcp-Protocol-Version"
	// HeaderSessionID carries the stateful MCP session identifier.
	HeaderSessionID = "Mcp-Session-Id"
	// HeaderLastEventID carries the resumable SSE event cursor.
	HeaderLastEventID = "Last-Event-ID"
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

type ownedJSONField struct {
	children map[string]ownedJSONField
}

var requestEnvelopeFields = map[string]ownedJSONField{
	"jsonrpc": {},
	"method":  {},
	"params": {children: map[string]ownedJSONField{
		"protocolVersion": {},
		"_meta": {children: map[string]ownedJSONField{
			MetaKeyProtocolVersion: {},
			MetaKeyClientCapabilities: {children: map[string]ownedJSONField{
				"sampling":    {},
				"roots":       {},
				"elicitation": {},
				"tasks":       {},
			}},
			MetaKeyClientInfo: {},
		}},
		"name": {},
		"uri":  {},
	}},
	"id": {},
}

// UnmarshalJSON preserves numeric identifiers without float64 rounding and
// rejects ambiguous spellings of fields interpreted by Gateway. Objects that
// Gateway treats as opaque, including tool arguments, retain normal JSON
// decoding semantics.
func (r *RequestEnvelope) UnmarshalJSON(data []byte) error {
	*r = RequestEnvelope{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	start, err := decoder.Token()
	if err != nil {
		return err
	}
	if start == nil {
		return requireJSONEOF(decoder)
	}
	if delimiter, ok := start.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("JSON-RPC request envelope must be an object")
	}

	seen := make(map[string]struct{}, len(requestEnvelopeFields))
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("JSON-RPC request envelope contains a non-string field name")
		}

		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
		canonical, rule, owned := matchOwnedJSONField(key, requestEnvelopeFields)
		if !owned {
			continue
		}
		if key != canonical {
			return fmt.Errorf("JSON-RPC request field %q must use canonical spelling %q", key, canonical)
		}
		if _, duplicate := seen[canonical]; duplicate {
			return fmt.Errorf("duplicate JSON-RPC request field %q", canonical)
		}
		seen[canonical] = struct{}{}
		if err := validateOwnedJSONObject(raw, "JSON-RPC request."+canonical, rule.children); err != nil {
			return err
		}

		switch canonical {
		case "jsonrpc":
			if err := json.Unmarshal(raw, &r.JSONRPC); err != nil {
				return err
			}
		case "method":
			if err := json.Unmarshal(raw, &r.Method); err != nil {
				return err
			}
		case "params":
			r.Params = append(r.Params[:0], raw...)
		case "id":
			if err := decodeJSONNumber(raw, &r.ID); err != nil {
				return err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func validateOwnedJSONObject(raw json.RawMessage, path string, fields map[string]ownedJSONField) error {
	if len(fields) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	start, err := decoder.Token()
	if err != nil {
		return err
	}
	if start == nil {
		return requireJSONEOF(decoder)
	}
	delimiter, object := start.(json.Delim)
	if !object || delimiter != '{' {
		// Shape validation belongs to the method-specific ingress checks. There
		// are no field names to disambiguate in a scalar or array value.
		return nil
	}

	seen := make(map[string]struct{}, len(fields))
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("%s contains a non-string field name", path)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		canonical, rule, owned := matchOwnedJSONField(key, fields)
		if !owned {
			continue
		}
		if key != canonical {
			return fmt.Errorf("field %q in %s must use canonical spelling %q", key, path, canonical)
		}
		if _, duplicate := seen[canonical]; duplicate {
			return fmt.Errorf("duplicate field %q in %s", canonical, path)
		}
		seen[canonical] = struct{}{}
		if err := validateOwnedJSONObject(value, path+"."+canonical, rule.children); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func matchOwnedJSONField(key string, fields map[string]ownedJSONField) (string, ownedJSONField, bool) {
	for canonical, rule := range fields {
		if strings.EqualFold(key, canonical) {
			return canonical, rule, true
		}
	}
	return "", ownedJSONField{}, false
}

func decodeJSONNumber(raw json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected data after JSON value")
		}
		return err
	}
	return nil
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
			c.Metadata = metadata
			c.ClientCapabilities = metadata[MetaKeyClientCapabilities]
			c.ClientInfo = metadata[MetaKeyClientInfo]
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

// IsModern reports an unambiguous modern protocol selection.
func (c *ProtocolContext) IsModern() bool {
	return c != nil && !c.DeclarationMismatch && c.EffectiveProtocolVersion == ModernProtocolVersion
}
