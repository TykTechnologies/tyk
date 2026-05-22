package oas

import (
	"encoding/json"
	"fmt"
	neturl "net/url"
	"strings"
)

// TykMCPServer configures a REST-as-MCP proxy's caller-facing primitive view.
type TykMCPServer struct {
	// Primitives configures proxy-specific source operation exposure and
	// metadata overrides.
	Primitives []TykMCPServerPrimitive `bson:"primitives,omitempty" json:"primitives,omitempty"`
}

// TykMCPServerPrimitive selects and overrides one source REST primitive in a
// proxy-specific MCP view. If no primitive has allow:true, the proxy exposes
// all source-derived primitives and applies entries here as metadata overrides.
// If any primitive has allow:true, only allow:true primitives are exposed.
type TykMCPServerPrimitive struct {
	// Source selects the REST operation this primitive configures.
	Source TykMCPServerSource `bson:"source,omitempty" json:"source,omitempty"`
	// Name overrides the caller-facing MCP tool name.
	Name string `bson:"name,omitempty" json:"name,omitempty"`
	// Description overrides the caller-facing MCP tool description.
	Description string `bson:"description,omitempty" json:"description,omitempty"`
	// Parameters overrides caller-facing MCP tool argument metadata.
	Parameters []TykMCPServerParameter `bson:"parameters,omitempty" json:"parameters,omitempty"`
	// Allow includes this primitive when explicit allow mode is active.
	Allow *bool `bson:"allow,omitempty" json:"allow,omitempty"`
}

// TykMCPServerSource identifies the source REST operation behind an MCP
// primitive. OperationID is preferred; path+method is accepted for source
// operations that do not define operationId.
type TykMCPServerSource struct {
	// OperationID selects a source operation by OpenAPI operationId.
	OperationID string `bson:"operationId,omitempty" json:"operationId,omitempty"`
	// Path selects a source operation by OpenAPI path when operationId is absent.
	Path string `bson:"path,omitempty" json:"path,omitempty"`
	// Method selects a source operation by HTTP method when operationId is absent.
	Method string `bson:"method,omitempty" json:"method,omitempty"`
}

// TykMCPServerParameter overrides one derived MCP input argument. Param names
// refer to derived argument names; Name is the caller-facing replacement.
type TykMCPServerParameter struct {
	// Param identifies the derived MCP argument to override.
	Param string `bson:"param,omitempty" json:"param,omitempty"`
	// Name replaces the caller-facing MCP argument name.
	Name string `bson:"name,omitempty" json:"name,omitempty"`
	// Description replaces the caller-facing MCP argument description.
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
	var parsed TykMCPServer
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	s.Extensions[ExtensionTykMCPServer] = &parsed
	return &parsed
}

// RemoveTykMCPServerExtension clears the REST-as-MCP proxy tool-view extension.
func (s *OAS) RemoveTykMCPServerExtension() {
	if s.Extensions == nil {
		return
	}

	delete(s.Extensions, ExtensionTykMCPServer)
}

func (s *OAS) validateMCPServerExtensionPlacement(isMCP bool) error {
	if s.GetTykMCPServerExtension() == nil {
		return nil
	}

	if !isMCP {
		return fmt.Errorf("%s is valid only for MCP proxies", ExtensionTykMCPServer)
	}

	ext := s.GetTykExtension()
	if ext == nil || !isMCPServerAdapterTarget(ext.Upstream.URL) {
		return fmt.Errorf("%s is valid only for MCP proxies targeting a REST-as-MCP adapter", ExtensionTykMCPServer)
	}

	return nil
}

func isMCPServerAdapterTarget(target string) bool {
	u, err := neturl.Parse(strings.TrimSpace(target))
	if err != nil || u.Scheme != "tyk" {
		return false
	}

	return IsAdapterAPIID(strings.TrimPrefix(u.Host, "id:"))
}
