package user

import "fmt"

// AccessControlRules defines allow/block name lists for ACL enforcement.
// Patterns in Allowed/Blocked are Go regexes anchored ^...$; exact strings work as-is.
type AccessControlRules struct {
	Allowed []string `json:"allowed,omitempty" msg:"allowed"`
	Blocked []string `json:"blocked,omitempty" msg:"blocked"`
}

// IsEmpty returns true if there are no access control rules configured.
func (a AccessControlRules) IsEmpty() bool {
	return len(a.Allowed) == 0 && len(a.Blocked) == 0
}

// IsZero implements the omitzero interface for JSON serialization.
func (a AccessControlRules) IsZero() bool {
	return a.IsEmpty()
}

// JSONRPCMethodLimit defines a per-JSON-RPC-method rate limit entry.
type JSONRPCMethodLimit struct {
	Name  string    `json:"name" msg:"name"`
	Limit RateLimit `json:"limit,omitzero" msg:"limit"`
}

// MCPPrimitiveLimit defines a per-MCP-primitive rate limit entry.
type MCPPrimitiveLimit struct {
	// Type is one of: "tool", "resource", "prompt".
	Type string `json:"type" msg:"type"`
	// Name is the primitive identifier (tool name, resource URI, prompt name).
	Name  string    `json:"name" msg:"name"`
	Limit RateLimit `json:"limit,omitzero" msg:"limit"`
}

var validMCPPrimitiveTypes = map[string]bool{
	"tool":     true,
	"resource": true,
	"prompt":   true,
}

// Validate returns an error if Type is not one of the known MCP primitive types.
func (m MCPPrimitiveLimit) Validate() error {
	if !validMCPPrimitiveTypes[m.Type] {
		return fmt.Errorf("invalid MCP primitive type %q: must be one of tool, resource, prompt", m.Type)
	}
	return nil
}

// MCPAccessRights defines MCP primitive access rights — one AccessControlRules per primitive type.
type MCPAccessRights struct {
	Tools     AccessControlRules `json:"tools,omitzero" msg:"tools"`
	Resources AccessControlRules `json:"resources,omitzero" msg:"resources"`
	Prompts   AccessControlRules `json:"prompts,omitzero" msg:"prompts"`
}

// IsEmpty returns true if there are no MCP access rights configured.
func (m MCPAccessRights) IsEmpty() bool {
	return m.Tools.IsEmpty() && m.Resources.IsEmpty() && m.Prompts.IsEmpty()
}

// IsZero implements the omitzero interface for JSON serialization.
func (m MCPAccessRights) IsZero() bool {
	return m.IsEmpty()
}
