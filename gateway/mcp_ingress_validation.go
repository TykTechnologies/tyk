package gateway

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

// validateMCPIngress validates modern protocol metadata and mirrored headers
// after the one bounded body parse and before routing reaches side effects.
func (m *JSONRPCMiddleware) validateMCPIngress(w http.ResponseWriter, r *http.Request) bool {
	protocolContext := httpctx.GetMCPProtocolContext(r)
	modern, ingressErr := mcp.ValidateProtocolDeclarations(protocolContext)
	if ingressErr != nil {
		m.writeMCPIngressError(w, r, ingressErr)
		return false
	}
	if !modern {
		return true
	}
	if ingressErr = mcp.ValidateModernMirroredHeaders(r.Header, protocolContext.Envelope); ingressErr != nil {
		m.writeMCPIngressError(w, r, ingressErr)
		return false
	}
	if m.Spec != nil && m.Spec.IsSyntheticMCPAdapter() {
		if ingressErr = m.validateRESTAsMCPParamHeaders(r, protocolContext.Envelope); ingressErr != nil {
			m.writeMCPIngressError(w, r, ingressErr)
			return false
		}
	}
	return true
}

func (m *JSONRPCMiddleware) writeMCPIngressError(w http.ResponseWriter, r *http.Request, ingressErr *mcp.IngressError) {
	protocolContext := httpctx.GetMCPProtocolContext(r)
	var requestID any
	if protocolContext != nil && protocolContext.Envelope != nil {
		requestID = protocolContext.Envelope.ID
	}
	m.writeJSONRPCError(w, r, requestID, ingressErr.Code, ingressErr.Message, ingressErr.Data)
}

func rejectModernMCPHTTPMethod(w http.ResponseWriter, r *http.Request) bool {
	protocolContext := httpctx.GetMCPProtocolContext(r)
	if protocolContext == nil || !protocolContext.IsModern() ||
		(r.Method != http.MethodGet && r.Method != http.MethodDelete) {
		return false
	}
	w.Header().Set("Allow", http.MethodPost)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	return true
}

type mcpParamHeaderBinding struct {
	path   []string
	header string
}

type mcpIngressTool struct {
	tool                oas.DerivedTool
	paramHeaderBindings []mcpParamHeaderBinding
}

func (m *JSONRPCMiddleware) validateRESTAsMCPParamHeaders(r *http.Request, envelope *mcp.RequestEnvelope) *mcp.IngressError {
	if envelope == nil || envelope.Method != mcp.MethodToolsCall {
		return nil
	}
	tool, found := m.restAsMCPIngressTool(r, envelope)
	if !found {
		return nil
	}
	bindings := tool.paramHeaderBindings
	expectedHeaders := make(map[string]struct{}, len(bindings))

	arguments, err := envelope.Arguments()
	if err != nil {
		return nil
	}

	for _, binding := range bindings {
		fullHeader := mcp.HeaderParamPrefix + binding.header
		expectedHeaders[strings.ToLower(fullHeader)] = struct{}{}
		argument, exists := nestedMCPArgument(arguments, binding.path)
		headerValue := r.Header.Get(fullHeader)
		if !exists || argument == nil {
			if headerValue != "" {
				return mcpParamHeaderMismatch()
			}
			continue
		}
		if headerValue == "" {
			return mcpParamHeaderMismatch()
		}
		decoded, valid := mcp.DecodeMirroredHeader(headerValue)
		if !valid {
			return mcpParamHeaderMismatch()
		}
		if !mcpPrimitiveHeaderMatches(argument, decoded) {
			return mcpParamHeaderMismatch()
		}
	}

	for header := range r.Header {
		if strings.HasPrefix(strings.ToLower(header), strings.ToLower(mcp.HeaderParamPrefix)) {
			if _, expected := expectedHeaders[strings.ToLower(header)]; !expected {
				return mcpParamHeaderMismatch()
			}
		}
	}
	return nil
}

func (m *JSONRPCMiddleware) restAsMCPIngressTool(r *http.Request, envelope *mcp.RequestEnvelope) (mcpIngressTool, bool) {
	name, ok := envelope.ParamString(mcp.ParamKeyName)
	if !ok || name == "" || m.Spec == nil {
		return mcpIngressTool{}, false
	}
	if callerID := ctxGetMCPAdapterCallerProxyID(r); callerID != "" {
		if tools, exists := m.Spec.MCPAdapter.IngressToolsByCaller[callerID]; exists {
			tool, found := tools[name]
			return tool, found
		}
	}
	tool, found := m.Spec.MCPAdapter.IngressToolsByCaller[""][name]
	return tool, found
}

func buildMCPIngressToolIndex(toolViews map[string]oas.MCPToolView, unionTools []oas.DerivedTool) map[string]map[string]mcpIngressTool {
	index := make(map[string]map[string]mcpIngressTool, len(toolViews)+1)
	add := func(callerID string, tools []oas.DerivedTool) {
		byName := make(map[string]mcpIngressTool, len(tools))
		for _, tool := range tools {
			byName[tool.Name] = mcpIngressTool{
				tool:                tool,
				paramHeaderBindings: collectMCPParamHeaderBindings(tool.InputSchema),
			}
		}
		index[callerID] = byName
	}
	add("", unionTools)
	for callerID, view := range toolViews {
		add(callerID, view.Tools)
	}
	return index
}

func collectMCPParamHeaderBindings(schema map[string]any) []mcpParamHeaderBinding {
	var bindings []mcpParamHeaderBinding
	var walk func(map[string]any, []string)
	walk = func(current map[string]any, prefix []string) {
		properties, _ := current["properties"].(map[string]any)
		for name, raw := range properties {
			property, _ := raw.(map[string]any)
			path := append(append([]string(nil), prefix...), name)
			if header, _ := property["x-mcp-header"].(string); header != "" {
				bindings = append(bindings, mcpParamHeaderBinding{path: path, header: header})
			}
			walk(property, path)
		}
	}
	walk(schema, nil)
	return bindings
}

func nestedMCPArgument(arguments map[string]any, path []string) (any, bool) {
	var current any = arguments
	for _, part := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func mcpPrimitiveString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case bool:
		return strconv.FormatBool(typed), true
	case json.Number:
		integer, err := strconv.ParseInt(typed.String(), 10, 64)
		if err == nil {
			if integer > 1<<53-1 || integer < -(1<<53-1) {
				return "", false
			}
			return strconv.FormatInt(integer, 10), true
		}
		floating, err := strconv.ParseFloat(typed.String(), 64)
		if err != nil || math.IsInf(floating, 0) || math.IsNaN(floating) {
			return "", false
		}
		return strconv.FormatFloat(floating, 'g', -1, 64), true
	default:
		return "", false
	}
}

func mcpPrimitiveHeaderMatches(value any, decodedHeader string) bool {
	expected, valid := mcpPrimitiveString(value)
	if !valid {
		return false
	}
	if expectedNumber, numeric := value.(json.Number); numeric {
		expectedValue, valid := mcpNumericValue(expectedNumber)
		if !valid {
			return false
		}
		actualValue, valid := mcpNumericValue(json.Number(decodedHeader))
		return valid && actualValue == expectedValue
	}
	return decodedHeader == expected
}

func mcpNumericValue(value json.Number) (float64, bool) {
	if integer, err := strconv.ParseInt(value.String(), 10, 64); err == nil {
		if integer > 1<<53-1 || integer < -(1<<53-1) {
			return 0, false
		}
		return float64(integer), true
	}
	floating, err := strconv.ParseFloat(value.String(), 64)
	if err != nil || math.IsInf(floating, 0) || math.IsNaN(floating) {
		return 0, false
	}
	if math.Trunc(floating) == floating && (floating > 1<<53-1 || floating < -(1<<53-1)) {
		return 0, false
	}
	return floating, true
}

func mcpParamHeaderMismatch() *mcp.IngressError {
	return &mcp.IngressError{Code: mcp.CodeHeaderMismatch, Message: "Mcp-Param headers do not match request parameters"}
}
