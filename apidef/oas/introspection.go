package oas

// MCPIntrospection configures automatic discovery of upstream MCP server capabilities.
type MCPIntrospection struct {
	// Enabled activates introspection for this MCP API.
	// When enabled, the gateway introspects the upstream MCP server at API load time
	// and via the on-demand POST /tyk/mcps/{apiID}/introspect endpoint.
	Enabled bool `bson:"enabled" json:"enabled"`

	// Timeout is the maximum duration for a single introspection cycle (e.g., "10s", "30s").
	// Default: "10s".
	Timeout string `bson:"timeout,omitempty" json:"timeout,omitempty"`

	// DiscoverTools enables discovery of tools. Default: true.
	DiscoverTools *bool `bson:"discoverTools,omitempty" json:"discoverTools,omitempty"`

	// DiscoverResources enables discovery of resources. Default: true.
	DiscoverResources *bool `bson:"discoverResources,omitempty" json:"discoverResources,omitempty"`

	// DiscoverPrompts enables discovery of prompts. Default: true.
	DiscoverPrompts *bool `bson:"discoverPrompts,omitempty" json:"discoverPrompts,omitempty"`
}

// GetTimeout returns the configured timeout or the default of "10s".
func (i *MCPIntrospection) GetTimeout() string {
	if i == nil || i.Timeout == "" {
		return "10s"
	}
	return i.Timeout
}

// ShouldDiscoverTools returns true if tool discovery is enabled (default: true).
func (i *MCPIntrospection) ShouldDiscoverTools() bool {
	if i == nil || i.DiscoverTools == nil {
		return true
	}
	return *i.DiscoverTools
}

// ShouldDiscoverResources returns true if resource discovery is enabled (default: true).
func (i *MCPIntrospection) ShouldDiscoverResources() bool {
	if i == nil || i.DiscoverResources == nil {
		return true
	}
	return *i.DiscoverResources
}

// ShouldDiscoverPrompts returns true if prompt discovery is enabled (default: true).
func (i *MCPIntrospection) ShouldDiscoverPrompts() bool {
	if i == nil || i.DiscoverPrompts == nil {
		return true
	}
	return *i.DiscoverPrompts
}
