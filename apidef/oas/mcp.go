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
// `tyk://<rest-apiid>__mcp-server`.
type MCP struct {
	// Enabled marks this REST API as MCP-callable.
	Enabled bool `bson:"enabled" json:"enabled"`

	// Expose is an optional allow-list of sanitised operationIds. When nil
	// or empty, every operation in the source OAS becomes a tool ("expose
	// all" default). When non-empty, only operations whose sanitised
	// operationId appears in the list are exposed.
	Expose []string `bson:"expose,omitempty" json:"expose,omitempty"`
}

// Fill fills *MCP from apidef.APIDefinition.
func (m *MCP) Fill(api apidef.APIDefinition) {
	m.Enabled = api.MCPExposure.Enabled
	m.Expose = api.MCPExposure.Expose
}

// ExtractTo extracts *MCP into *apidef.APIDefinition.
func (m *MCP) ExtractTo(api *apidef.APIDefinition) {
	api.MCPExposure.Enabled = m.Enabled
	api.MCPExposure.Expose = m.Expose
}
