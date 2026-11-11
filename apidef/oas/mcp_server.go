package oas

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// TykMCPServer configures a REST-as-MCP proxy's caller-facing primitive view.
type TykMCPServer struct {
	// Primitives configures proxy-side source selection and metadata overrides.
	Primitives []TykMCPServerPrimitive `bson:"primitives,omitempty" json:"primitives,omitempty"`
}

// TykMCPServerPrimitive selects and overrides one source REST primitive in a
// proxy-specific MCP view. If no primitive has allow:true, the proxy exposes
// all source-derived primitives and applies entries here as metadata overrides.
// If any primitive has allow:true, only allow:true primitives are exposed.
type TykMCPServerPrimitive struct {
	// Source selects the source REST operation for this primitive.
	Source TykMCPServerSource `bson:"source,omitempty" json:"source,omitempty"`
	// Name overrides the derived MCP-facing tool name.
	Name string `bson:"name,omitempty" json:"name,omitempty"`
	// Description overrides the derived MCP-facing tool description.
	Description string `bson:"description,omitempty" json:"description,omitempty"`
	// Annotations overrides MCP tool annotations derived from the source operation.
	Annotations *DerivedToolAnnotations `bson:"annotations,omitempty" json:"annotations,omitempty"`
	// Parameters configures MCP-facing argument names and descriptions.
	Parameters []TykMCPServerParameter `bson:"parameters,omitempty" json:"parameters,omitempty"`
	// Allow exposes this primitive when any primitive uses explicit allow mode.
	Allow *bool `bson:"allow,omitempty" json:"allow,omitempty"`

	// InputSchema is populated in expanded responses with the final MCP tool input schema.
	InputSchema map[string]any `bson:"-" json:"inputSchema,omitempty"`
	// OutputSchema is populated in expanded responses with the final MCP tool output schema.
	OutputSchema map[string]any `bson:"-" json:"outputSchema,omitempty"`
	// ParameterLocations maps final MCP parameter names to their source REST location in expanded responses.
	ParameterLocations map[string]string `bson:"-" json:"parameterLocations,omitempty"`
	// ParameterSourceNames maps final MCP parameter names to their original REST names in expanded responses.
	ParameterSourceNames map[string]string `bson:"-" json:"parameterSourceNames,omitempty"`
	// ParameterSerializations describes final path/query/header serialization in expanded responses.
	ParameterSerializations map[string]DerivedParamSerialization `bson:"-" json:"parameterSerializations,omitempty"`
	// ParameterOrder preserves final parameter order in expanded responses.
	ParameterOrder []string `bson:"-" json:"parameterOrder,omitempty"`
	// RequestBodyContentType is populated in expanded responses when the source request body has a selected media type.
	RequestBodyContentType string `bson:"-" json:"requestBodyContentType,omitempty"`
}

// TykMCPServerSource identifies the source REST operation behind an MCP
// primitive. OperationID is preferred; path+method is accepted for source
// operations that do not define operationId.
type TykMCPServerSource struct {
	// OperationID selects a source REST operation by operationId.
	OperationID string `bson:"operationId,omitempty" json:"operationId,omitempty"`
	// Path selects a source REST operation by OAS path template.
	Path string `bson:"path,omitempty" json:"path,omitempty"`
	// Method selects a source REST operation by HTTP method.
	Method string `bson:"method,omitempty" json:"method,omitempty"`
	// ToolName selects an upstream tool by name on a remote MCP proxy. It is
	// mutually exclusive with the REST selectors above.
	ToolName string `bson:"toolName,omitempty" json:"toolName,omitempty"`
}

// TykMCPServerParameter overrides one derived MCP input argument. Param names
// refer to derived argument names; Name is the caller-facing replacement.
type TykMCPServerParameter struct {
	// Param identifies the derived MCP argument to override.
	Param string `bson:"param,omitempty" json:"param,omitempty"`
	// Name overrides the MCP-facing argument name.
	Name string `bson:"name,omitempty" json:"name,omitempty"`
	// Description overrides the MCP-facing argument description.
	Description string `bson:"description,omitempty" json:"description,omitempty"`
}

// SetTykMCPServerExtension populates the proxy-side REST-as-MCP extension.
func (s *OAS) SetTykMCPServerExtension(ext *TykMCPServer) {
	if s.Extensions == nil {
		s.Extensions = make(map[string]interface{})
	}

	s.Extensions[ExtensionTykMCPServer] = ext
}

// GetTykMCPServerExtension returns the parsed REST-as-MCP proxy tool-view
// extension, if present.
func (s *OAS) GetTykMCPServerExtension() *TykMCPServer {
	if s.Extensions == nil {
		return nil
	}

	ext := s.Extensions[ExtensionTykMCPServer]
	if ext == nil {
		return nil
	}

	switch v := ext.(type) {
	case *TykMCPServer:
		return v
	case TykMCPServer:
		s.Extensions[ExtensionTykMCPServer] = &v
		return &v
	case json.RawMessage:
		return s.cacheTykMCPServerExtension(v)
	case []byte:
		return s.cacheTykMCPServerExtension(v)
	case map[string]interface{}:
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return s.cacheTykMCPServerExtension(b)
	default:
		return nil
	}
}

func (s *OAS) cacheTykMCPServerExtension(raw []byte) *TykMCPServer {
	parsed, err := decodeTykMCPServer(raw)
	if err != nil {
		return nil
	}
	s.Extensions[ExtensionTykMCPServer] = parsed
	return parsed
}

// decodeTykMCPServerExtension is GetTykMCPServerExtension with the decode
// error kept, so validation can report a malformed extension instead of
// silently treating it as absent.
func (s *OAS) decodeTykMCPServerExtension() (*TykMCPServer, error) {
	if ext := s.GetTykMCPServerExtension(); ext != nil {
		return ext, nil
	}

	raw, err := json.Marshal(s.Extensions[ExtensionTykMCPServer])
	if err != nil {
		return nil, fmt.Errorf("%s is invalid: %w", ExtensionTykMCPServer, err)
	}
	_, err = decodeTykMCPServer(raw)
	return nil, err
}

func decodeTykMCPServer(raw []byte) (*TykMCPServer, error) {
	var parsed TykMCPServer
	err := json.Unmarshal(raw, &parsed)
	if err == nil {
		return &parsed, nil
	}

	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) && typeErr.Field != "" {
		kind := "a " + typeErr.Type.Kind().String()
		if typeErr.Type.Kind() == reflect.Bool {
			kind = "a boolean"
		}
		return nil, fmt.Errorf("%s field %s must be %s", ExtensionTykMCPServer, typeErr.Field, kind)
	}
	return nil, fmt.Errorf("%s is invalid: %w", ExtensionTykMCPServer, err)
}

// RemoveTykMCPServerExtension clears the REST-as-MCP proxy tool-view extension.
func (s *OAS) RemoveTykMCPServerExtension() {
	if s.Extensions == nil {
		return
	}

	delete(s.Extensions, ExtensionTykMCPServer)
}

// CompactTykMCPServerExtension removes response-only expansion fields before persistence.
func (s *OAS) CompactTykMCPServerExtension() {
	ext := s.GetTykMCPServerExtension()
	if ext == nil {
		return
	}

	compact := CompactTykMCPServer(ext)
	if compact == nil || len(compact.Primitives) == 0 {
		s.RemoveTykMCPServerExtension()
		return
	}

	s.SetTykMCPServerExtension(compact)
}

// CompactTykMCPServer returns a storage-safe copy of an MCP server extension.
func CompactTykMCPServer(ext *TykMCPServer) *TykMCPServer {
	if ext == nil {
		return nil
	}

	compact := &TykMCPServer{
		Primitives: make([]TykMCPServerPrimitive, 0, len(ext.Primitives)),
	}
	for _, primitive := range ext.Primitives {
		if primitive.Allow != nil && !*primitive.Allow && primitive.hasExpandedResponseFields() {
			continue
		}

		compact.Primitives = append(compact.Primitives, TykMCPServerPrimitive{
			Source:      primitive.Source,
			Name:        primitive.Name,
			Description: primitive.Description,
			Annotations: cloneDerivedToolAnnotations(primitive.Annotations),
			Parameters:  append([]TykMCPServerParameter(nil), primitive.Parameters...),
			Allow:       cloneBoolPtr(primitive.Allow),
		})
	}

	return compact
}

func (p TykMCPServerPrimitive) hasExpandedResponseFields() bool {
	return p.InputSchema != nil ||
		p.OutputSchema != nil ||
		p.ParameterLocations != nil ||
		p.ParameterSourceNames != nil ||
		p.ParameterSerializations != nil ||
		p.ParameterOrder != nil ||
		p.RequestBodyContentType != ""
}

func cloneBoolPtr(src *bool) *bool {
	if src == nil {
		return nil
	}
	dst := *src
	return &dst
}

func (s *OAS) validateMCPServerExtensionPlacement(isMCP bool) error {
	if s.Extensions == nil || s.Extensions[ExtensionTykMCPServer] == nil {
		return nil
	}

	if !isMCP {
		return fmt.Errorf("%s is valid only for MCP proxies", ExtensionTykMCPServer)
	}

	mcpServer, err := s.decodeTykMCPServerExtension()
	if err != nil || mcpServer == nil {
		return err
	}

	ext := s.GetTykExtension()
	if ext == nil || !isMCPServerAdapterTarget(ext.Upstream.URL) {
		return ValidateRemoteMCPToolOverrides(mcpServer)
	}

	for i, primitive := range mcpServer.Primitives {
		if primitive.Source.ToolName != "" {
			return fmt.Errorf("%s primitive %d: source.toolName is valid only for remote MCP proxies; REST-as-MCP proxies select operations by operationId or path+method", ExtensionTykMCPServer, i)
		}
	}
	return nil
}

func isMCPServerAdapterTarget(target string) bool {
	_, _, ok := ParseAdapterTarget(target)
	return ok
}
