package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
func ValidateProtocolDeclarations(protocolContext *ProtocolContext) (bool, *IngressError) {
	if protocolContext == nil {
		return false, nil
	}
	modernRequested := protocolContext.HeaderProtocolVersion == ModernProtocolVersion ||
		protocolContext.MetadataProtocolVersion == ModernProtocolVersion ||
		protocolContext.InitializeProtocolVersion == ModernProtocolVersion

	if modernRequested && (!protocolContext.MetadataProtocolPresent || !protocolContext.MetadataProtocolValid) {
		return true, &IngressError{
			Code:    JSONRPCInvalidParams,
			Message: fmt.Sprintf("missing or invalid _meta field %q", MetaKeyProtocolVersion),
		}
	}
	if protocolContext.DeclarationMismatch {
		return modernRequested, &IngressError{Code: CodeHeaderMismatch, Message: "Mcp-Protocol-Version header does not match the request body"}
	}

	version := protocolContext.EffectiveProtocolVersion
	if version != "" && !IsServedProtocolVersion(version) {
		return modernRequested, &IngressError{
			Code:    CodeUnsupportedProtocolVersion,
			Message: "unsupported protocol version",
			Data: map[string]any{
				"requested": version,
				"supported": ServedProtocolVersions(),
			},
		}
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
	if len(protocolContext.ClientInfo) > 0 {
		var clientInfo map[string]json.RawMessage
		if json.Unmarshal(protocolContext.ClientInfo, &clientInfo) != nil || clientInfo == nil {
			return true, &IngressError{
				Code:    JSONRPCInvalidParams,
				Message: fmt.Sprintf("invalid _meta field %q", MetaKeyClientInfo),
			}
		}
	}

	if required := requiredClientCapability(protocolContext.Envelope); required != "" {
		if raw, present := capabilities[required]; !present || string(raw) == "null" {
			return true, &IngressError{
				Code:    CodeMissingRequiredClientCapabilities,
				Message: "missing required client capability",
				Data:    map[string]any{"requiredCapabilities": map[string]any{required: map[string]any{}}},
			}
		}
	}

	return true, nil
}

func requiredClientCapability(envelope *RequestEnvelope) string {
	if envelope == nil {
		return ""
	}
	switch envelope.Method {
	case MethodSamplingCreateMessage:
		return "sampling"
	case "roots/list":
		return "roots"
	case "elicitation/create":
		return "elicitation"
	default:
		return ""
	}
}

// ValidateModernMirroredHeaders validates Mcp-Method, conditional Mcp-Name,
// and the syntax/encoding of Mcp-Param-* headers.
func ValidateModernMirroredHeaders(header http.Header, envelope *RequestEnvelope) *IngressError {
	if envelope == nil {
		return &IngressError{Code: JSONRPCInvalidParams, Message: "missing JSON-RPC request envelope"}
	}
	method, ok := DecodeMirroredHeader(header.Get(HeaderMethod))
	if !ok || method == "" {
		return &IngressError{Code: CodeHeaderMismatch, Message: "missing or malformed Mcp-Method header"}
	}
	if method != envelope.Method {
		return &IngressError{Code: CodeHeaderMismatch, Message: fmt.Sprintf("Mcp-Method header value %q does not match body value %q", method, envelope.Method)}
	}

	if name, required := primitiveName(envelope); required {
		headerName, valid := DecodeMirroredHeader(header.Get(HeaderName))
		if !valid || headerName == "" {
			return &IngressError{Code: CodeHeaderMismatch, Message: fmt.Sprintf("missing or malformed Mcp-Name header for method %q", envelope.Method)}
		}
		if headerName != name {
			return &IngressError{Code: CodeHeaderMismatch, Message: fmt.Sprintf("Mcp-Name header value %q does not match body value %q", headerName, name)}
		}
	}

	for key, values := range header {
		if !strings.HasPrefix(strings.ToLower(key), strings.ToLower(HeaderParamPrefix)) {
			continue
		}
		if !validHeaderToken(key[len(HeaderParamPrefix):]) || len(values) != 1 {
			return &IngressError{Code: CodeHeaderMismatch, Message: fmt.Sprintf("malformed %s header", key)}
		}
		if _, valid := DecodeMirroredHeader(values[0]); !valid {
			return &IngressError{Code: CodeHeaderMismatch, Message: fmt.Sprintf("%s header contains invalid Base64 encoding", key)}
		}
	}
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
		return value, true
	}
	if !starts || !ends || len(value) < len(prefix)+len(suffix) {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix))
	if err != nil {
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

func validHeaderToken(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}
