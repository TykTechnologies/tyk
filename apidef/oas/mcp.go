package oas

import "github.com/TykTechnologies/tyk/apidef"

// MCP is the OAS-side marker that this REST API should be exposed as MCP.
//
// When Enabled is true, the gateway loader will synthesise a paired
// Internal adapter spec with APIID `<rest-apiid>__mcp-server`. The adapter
// answers JSON-RPC `initialize`, `ping`, and `tools/list` inline, and
// translates `tools/call` into an HTTP request that is looped back through
// this REST API's full middleware chain.
//
// The actual MCP listener (auth, rate-limit, etc.) is a separate operator-
// managed APIDef POSTed to /tyk/mcps whose upstream URL is
// `tyk://id:<rest-apiid>__mcp-server`.
type MCP struct {
	// Enabled marks this REST API as MCP-callable.
	Enabled bool `bson:"enabled" json:"enabled"`

	// Curation selects which operations become tools.
	// Allowed values: "expose-all" (default), "strict-opt-in".
	// When "strict-opt-in", only operations whose sanitized operationId
	// appears as a key in Middleware.McpTools are exposed.
	Curation string `bson:"curation,omitempty" json:"curation,omitempty"`
}

// Fill fills *MCP from apidef.APIDefinition.
func (m *MCP) Fill(api apidef.APIDefinition) {
	m.Enabled = api.MCPExposure.Enabled
	m.Curation = api.MCPExposure.Curation
}

// ExtractTo extracts *MCP into *apidef.APIDefinition.
func (m *MCP) ExtractTo(api *apidef.APIDefinition) {
	api.MCPExposure.Enabled = m.Enabled
	api.MCPExposure.Curation = m.Curation
}
