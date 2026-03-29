package client

// ServerCapabilities holds all discovered primitives from an MCP server.
type ServerCapabilities struct {
	Tools      []ToolInfo     `json:"tools,omitempty"`
	Resources  []ResourceInfo `json:"resources,omitempty"`
	Prompts    []PromptInfo   `json:"prompts,omitempty"`
	ServerInfo ServerInfo     `json:"serverInfo"`
}

// ToolInfo describes a tool exposed by the MCP server.
type ToolInfo struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

// ResourceInfo describes a resource exposed by the MCP server.
type ResourceInfo struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// PromptInfo describes a prompt template exposed by the MCP server.
type PromptInfo struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// PromptArgument describes a single argument for a prompt template.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// ServerInfo contains identity information about the upstream MCP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// IntrospectionResult wraps the result of an introspection cycle.
type IntrospectionResult struct {
	Capabilities *ServerCapabilities  `json:"capabilities"`
	Errors       []IntrospectionError `json:"errors,omitempty"`
	Partial      bool                 `json:"partial"`
}

// IntrospectionError records a failure for a specific JSON-RPC method.
type IntrospectionError struct {
	Method string `json:"method"`
	Err    string `json:"error"`
}
