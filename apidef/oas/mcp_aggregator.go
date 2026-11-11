package oas

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

// MCPAggregatorTargetURL is the reserved upstream URL of an MCP aggregator.
const MCPAggregatorTargetURL = apidef.MCPAggregatorTargetURL

// TykMCPAggregator configures an MCP proxy that serves the combined tool
// catalogue of other MCP proxies loaded on the same gateway.
type TykMCPAggregator struct {
	// Upstreams lists the aggregated MCP proxies.
	Upstreams []TykMCPAggregatorUpstream `bson:"upstreams" json:"upstreams"`
}

// TykMCPAggregatorUpstream references one aggregated MCP proxy.
type TykMCPAggregatorUpstream struct {
	// APIID is the ID of the aggregated MCP proxy.
	APIID string `bson:"apiId" json:"apiId"`
	// Alias prefixes the aggregated proxy's tool names as `<alias>__<tool>`.
	Alias string `bson:"alias" json:"alias"`
	// Tools selects tools of the aggregated proxy. Omitted means all tools.
	Tools []string `bson:"tools,omitempty" json:"tools,omitempty"`
}

// SetTykMCPAggregatorExtension populates the MCP aggregator extension.
func (s *OAS) SetTykMCPAggregatorExtension(ext *TykMCPAggregator) {
	if s.Extensions == nil {
		s.Extensions = make(map[string]interface{})
	}

	s.Extensions[ExtensionTykMCPAggregator] = ext
}

// GetTykMCPAggregatorExtension returns the parsed MCP aggregator extension, if present.
func (s *OAS) GetTykMCPAggregatorExtension() *TykMCPAggregator {
	if s.Extensions == nil {
		return nil
	}

	ext := s.Extensions[ExtensionTykMCPAggregator]
	if ext == nil {
		return nil
	}

	switch v := ext.(type) {
	case *TykMCPAggregator:
		return v
	case TykMCPAggregator:
		s.Extensions[ExtensionTykMCPAggregator] = &v
		return &v
	case json.RawMessage:
		return s.cacheTykMCPAggregatorExtension(v)
	case []byte:
		return s.cacheTykMCPAggregatorExtension(v)
	case map[string]interface{}:
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return s.cacheTykMCPAggregatorExtension(b)
	default:
		return nil
	}
}

func (s *OAS) cacheTykMCPAggregatorExtension(raw []byte) *TykMCPAggregator {
	var parsed TykMCPAggregator
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	s.Extensions[ExtensionTykMCPAggregator] = &parsed
	return &parsed
}

// RemoveTykMCPAggregatorExtension clears the MCP aggregator extension.
func (s *OAS) RemoveTykMCPAggregatorExtension() {
	if s.Extensions == nil {
		return
	}

	delete(s.Extensions, ExtensionTykMCPAggregator)
}

func (s *OAS) validateMCPAggregatorExtension(isMCP bool) error {
	ext := s.GetTykMCPAggregatorExtension()
	upstreamURL := ""
	if tyk := s.GetTykExtension(); tyk != nil {
		upstreamURL = strings.TrimSpace(tyk.Upstream.URL)
	}

	// Without the extension the reserved URL stays an ordinary loop to an API
	// named "mcp-aggregator", as it was before aggregators existed.
	if ext == nil {
		return nil
	}

	if !isMCP {
		return fmt.Errorf("%s is valid only for MCP proxies", ExtensionTykMCPAggregator)
	}
	if s.GetTykMCPServerExtension() != nil {
		return fmt.Errorf("%s and %s cannot be configured on the same MCP proxy", ExtensionTykMCPAggregator, ExtensionTykMCPServer)
	}
	if upstreamURL != MCPAggregatorTargetURL {
		return fmt.Errorf("%s requires upstream.url %q", ExtensionTykMCPAggregator, MCPAggregatorTargetURL)
	}

	return nil
}
