package oas

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

// MCPAggregatorTargetURL is the reserved upstream URL of an MCP aggregator.
const MCPAggregatorTargetURL = apidef.MCPAggregatorTargetURL

// MaxMCPAggregatorUpstreams is the most aggregated MCP proxies one aggregator
// may list. The JSON schema enforces the same limit.
const MaxMCPAggregatorUpstreams = 50

var mcpAggregatorAliasPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// TykMCPAggregator configures an MCP proxy that serves the combined tool
// catalogue of other MCP proxies loaded on the same gateway.
type TykMCPAggregator struct {
	// Upstreams lists the aggregated MCP proxies.
	Upstreams []TykMCPAggregatorUpstream `bson:"upstreams,omitempty" json:"upstreams,omitempty"`
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

	return ValidateTykMCPAggregator(ext)
}

// ValidateTykMCPAggregator validates the aggregator settings that do not
// depend on other APIs loaded on the gateway.
func ValidateTykMCPAggregator(ext *TykMCPAggregator) error {
	if ext == nil {
		return nil
	}
	if len(ext.Upstreams) == 0 {
		return fmt.Errorf("%s.upstreams: at least one aggregated MCP proxy is required", ExtensionTykMCPAggregator)
	}
	if len(ext.Upstreams) > MaxMCPAggregatorUpstreams {
		return fmt.Errorf("%s.upstreams: at most %d aggregated MCP proxies are allowed", ExtensionTykMCPAggregator, MaxMCPAggregatorUpstreams)
	}

	aliases := make(map[string]struct{}, len(ext.Upstreams))
	apiIDs := make(map[string]struct{}, len(ext.Upstreams))
	for idx, upstream := range ext.Upstreams {
		field := fmt.Sprintf("%s.upstreams[%d]", ExtensionTykMCPAggregator, idx)
		if strings.TrimSpace(upstream.APIID) == "" {
			return fmt.Errorf("%s.apiId is required", field)
		}
		if _, duplicate := apiIDs[upstream.APIID]; duplicate {
			return fmt.Errorf("%s.apiId %q is duplicated: each aggregated MCP proxy may be listed only once", field, upstream.APIID)
		}
		apiIDs[upstream.APIID] = struct{}{}
		if upstream.Alias == "" {
			return fmt.Errorf("%s.alias is required", field)
		}
		if !mcpAggregatorAliasPattern.MatchString(upstream.Alias) {
			return fmt.Errorf("%s.alias %q is invalid: aliases may contain only lowercase letters, digits and hyphens", field, upstream.Alias)
		}
		if _, duplicate := aliases[upstream.Alias]; duplicate {
			return fmt.Errorf("%s.alias %q is duplicated: aliases must be unique", field, upstream.Alias)
		}
		aliases[upstream.Alias] = struct{}{}
		if upstream.Tools != nil && len(upstream.Tools) == 0 {
			return fmt.Errorf("%s.tools: select at least one tool or omit the field", field)
		}
	}

	return nil
}
