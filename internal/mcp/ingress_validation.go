package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MetaKeyClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	MetaKeyClientInfo         = "io.modelcontextprotocol/clientInfo"

	HeaderMethod      = "Mcp-Method"
	HeaderName        = "Mcp-Name"
	HeaderParamPrefix = "Mcp-Param-"

	CodeHeaderMismatch                    = -32020
	CodeMissingRequiredClientCapabilities = -32021
	CodeUnsupportedProtocolVersion        = -32022
)

// IngressError is a JSON-RPC rejection produced before request side effects.
type IngressError struct {
	Code    int
	Message string
	Data    any
}

// ValidateProtocolDeclarations validates version agreement, metadata shape,
// and supported versions. It returns whether modern mirrored-header validation
// applies to the request.
func ValidateProtocolDeclarations(protocolContext *ProtocolContext, endpoints ...ProtocolSupport) (bool, *IngressError) {
	if protocolContext == nil {
		return false, nil
	}
	modernRequested := protocolContext.HeaderProtocolVersion == ModernProtocolVersion ||
		protocolContext.MetadataProtocolVersion == ModernProtocolVersion ||
		protocolContext.InitializeProtocolVersion == ModernProtocolVersion

	versions := ServedProtocolVersions()
	if len(endpoints) > 0 && endpoints[0] != nil {
		versions = endpoints[0].SupportedProtocolVersions()
	}
	version := protocolContext.EffectiveProtocolVersion
	if modernRequested && !slices.Contains(versions, ModernProtocolVersion) {
		return true, unsupportedProtocol(ModernProtocolVersion, versions)
	}
	if modernRequested && (!protocolContext.MetadataProtocolPresent || !protocolContext.MetadataProtocolValid) {
		return true, &IngressError{Code: JSONRPCInvalidParams, Message: fmt.Sprintf("missing or invalid _meta field %q", MetaKeyProtocolVersion)}
	}
	if protocolContext.DeclarationMismatch {
		return modernRequested, &IngressError{Code: CodeHeaderMismatch, Message: "conflicting MCP protocol declarations"}
	}
	// Legacy initialize negotiates an offered version upstream. Preserve that
	// behavior for unrecognized body-only offers without modern metadata.
	legacyNegotiation := !modernRequested && protocolContext.Envelope != nil && protocolContext.Envelope.Method == MethodInitialize && protocolContext.HeaderProtocolVersion == "" && !protocolContext.MetadataProtocolPresent
	if version != "" && !slices.Contains(versions, version) && !legacyNegotiation {
		return modernRequested, unsupportedProtocol(version, versions)
	}
	if !modernRequested {
		return false, nil
	}
	if protocolContext.HeaderProtocolVersion == "" || protocolContext.HeaderProtocolVersion != protocolContext.MetadataProtocolVersion {
		return true, &IngressError{Code: CodeHeaderMismatch, Message: "missing or mismatched Mcp-Protocol-Version header"}
	}

	var capabilities map[string]json.RawMessage
	if len(protocolContext.ClientCapabilities) == 0 ||
		json.Unmarshal(protocolContext.ClientCapabilities, &capabilities) != nil || capabilities == nil {
		return true, &IngressError{
			Code:    JSONRPCInvalidParams,
			Message: fmt.Sprintf("missing or invalid _meta field %q", MetaKeyClientCapabilities),
		}
	}
	for _, key := range []string{"sampling", "roots", "elicitation", "tasks"} {
		if raw, exists := capabilities[key]; exists {
			var value map[string]json.RawMessage
			if json.Unmarshal(raw, &value) != nil || value == nil {
				return true, &IngressError{Code: JSONRPCInvalidParams, Message: "invalid client capability metadata"}
			}
		}
	}
	if len(protocolContext.ClientInfo) > 0 {
		var clientInfo map[string]json.RawMessage
		if json.Unmarshal(protocolContext.ClientInfo, &clientInfo) != nil || clientInfo == nil {
			return true, &IngressError{
				Code:    JSONRPCInvalidParams,
				Message: fmt.Sprintf("invalid _meta field %q", MetaKeyClientInfo),
			}
		}
	}

	// Gateway owns no sampling, roots, or elicitation callbacks on native
	// proxy endpoints. Requirements for upstream-owned features stay upstream.
	if protocolContext.Envelope != nil {
		switch protocolContext.Envelope.Method {
		case "initialize", "ping", "notifications/initialized", "notifications/roots/list_changed", "logging/setLevel", "resources/subscribe", "resources/unsubscribe":
			return true, &IngressError{Code: JSONRPCMethodNotFound, Message: "method removed in the modern protocol"}
		}
	}
	return true, nil
}

func unsupportedProtocol(version string, supported []string) *IngressError {
	return &IngressError{Code: CodeUnsupportedProtocolVersion, Message: "unsupported protocol version", Data: map[string]any{"requested": version, "supported": supported}}
}

// ValidateProtocolHeader rejects ambiguous declarations before policy effects.
func ValidateProtocolHeader(header http.Header) *IngressError {
	values := headerValues(header, HeaderProtocolVersion)
	if len(values) == 0 {
		return nil
	}
	if len(values) != 1 {
		return &IngressError{Code: CodeHeaderMismatch, Message: "multiple MCP-Protocol-Version headers"}
	}
	value := values[0]
	if _, err := time.Parse("2006-01-02", value); err != nil {
		return &IngressError{Code: CodeHeaderMismatch, Message: "malformed MCP-Protocol-Version header"}
	}
	return nil
}

func headerValues(header http.Header, key string) []string {
	var values []string
	for name, entries := range header {
		if strings.EqualFold(name, key) {
			values = append(values, entries...)
		}
	}
	return values
}

// ValidateModernMirroredHeaders validates Mcp-Method, conditional Mcp-Name,
// including their multiplicity, encoding and agreement with the body.
func ValidateModernMirroredHeaders(header http.Header, envelope *RequestEnvelope) *IngressError {
	if envelope == nil {
		return &IngressError{Code: JSONRPCInvalidParams, Message: "missing JSON-RPC request envelope"}
	}
	methods := headerValues(header, HeaderMethod)
	if len(methods) != 1 {
		return &IngressError{Code: CodeHeaderMismatch, Message: "missing or multiple Mcp-Method headers"}
	}
	method, ok := DecodeMirroredHeader(methods[0])
	if !ok || method == "" {
		return &IngressError{Code: CodeHeaderMismatch, Message: "missing or malformed Mcp-Method header"}
	}
	if method != envelope.Method {
		return &IngressError{Code: CodeHeaderMismatch, Message: "Mcp-Method header does not match body"}
	}

	if names := headerValues(header, HeaderName); len(names) > 0 {
		if len(names) != 1 {
			return &IngressError{Code: CodeHeaderMismatch, Message: "multiple Mcp-Name headers"}
		}
		if _, valid := DecodeMirroredHeader(names[0]); !valid {
			return &IngressError{Code: CodeHeaderMismatch, Message: "malformed Mcp-Name header"}
		}
	}
	if name, required := primitiveName(envelope); required {
		names := headerValues(header, HeaderName)
		if len(names) != 1 {
			return &IngressError{Code: CodeHeaderMismatch, Message: "missing or multiple Mcp-Name headers"}
		}
		headerName, valid := DecodeMirroredHeader(names[0])
		if !valid || headerName == "" {
			return &IngressError{Code: CodeHeaderMismatch, Message: fmt.Sprintf("missing or malformed Mcp-Name header for method %q", envelope.Method)}
		}
		if headerName != name {
			return &IngressError{Code: CodeHeaderMismatch, Message: "Mcp-Name header does not match body"}
		}
	}

	// Unknown custom Mcp-Param-* bindings are forwarded without interpretation.
	// Their upstream schema, not Gateway, defines their values and multiplicity.

	return nil
}

// DecodeMirroredHeader decodes the SEP-2243 Base64 wrapper. Partial wrappers
// and invalid payloads are rejected rather than compared as literal text.
func DecodeMirroredHeader(value string) (string, bool) {
	const prefix = "=?base64?"
	const suffix = "?="
	starts := strings.HasPrefix(value, prefix)
	ends := strings.HasSuffix(value, suffix)
	if !starts && !ends {
		if !utf8.ValidString(value) {
			return "", false
		}
		for _, char := range value {
			if char < 0x20 || char > 0x7e {
				return "", false
			}
		}
		return value, true
	}
	if !starts || !ends || len(value) < len(prefix)+len(suffix) {
		return "", false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix))
	if err != nil || !utf8.Valid(decoded) {
		return "", false
	}
	return string(decoded), true
}

func primitiveName(envelope *RequestEnvelope) (string, bool) {
	var field string
	switch envelope.Method {
	case MethodToolsCall, MethodPromptsGet:
		field = "name"
	case MethodResourcesRead:
		field = "uri"
	default:
		return "", false
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(envelope.Params, &params) != nil {
		return "", true
	}
	var name string
	if json.Unmarshal(params[field], &name) != nil {
		return "", true
	}
	return name, true
}
