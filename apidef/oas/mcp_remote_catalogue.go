package oas

import (
	"fmt"
)

// RemoteMCPToolCollision is an override whose final name is also the name of
// an upstream tool that has no override of its own.
type RemoteMCPToolCollision struct {
	// Name is the name both tools would be exposed under.
	Name string
	// Source is the upstream tool the override renames to Name.
	Source string
}

// InspectRemoteMCPToolCatalogue compares a remote MCP proxy's tool overrides
// with the complete upstream tool catalogue (every tools/list page).
//
// It returns, in configuration order, the sources of overrides that are not in
// the catalogue, which expose nothing, and the overrides whose final name is
// also the name of an untouched upstream tool. Use
// ValidateRemoteMCPToolOverrides for the checks that need no catalogue.
func InspectRemoteMCPToolCatalogue(ext *TykMCPServer, upstreamToolNames []string) (missingSources []string, collisions []RemoteMCPToolCollision) {
	if ext == nil || len(ext.Primitives) == 0 {
		return nil, nil
	}

	upstream := make(map[string]struct{}, len(upstreamToolNames))
	for _, name := range upstreamToolNames {
		upstream[name] = struct{}{}
	}

	overridden := make(map[string]struct{}, len(ext.Primitives))
	for _, primitive := range ext.Primitives {
		overridden[primitive.Source.ToolName] = struct{}{}
	}

	for _, primitive := range ext.Primitives {
		source := primitive.Source.ToolName
		if _, ok := upstream[source]; !ok {
			missingSources = append(missingSources, source)
			continue
		}
		if primitive.Name == "" || primitive.Name == source {
			continue
		}
		if _, untouched := upstream[primitive.Name]; untouched {
			if _, ok := overridden[primitive.Name]; !ok {
				collisions = append(collisions, RemoteMCPToolCollision{Name: primitive.Name, Source: source})
			}
		}
	}
	return missingSources, collisions
}

// CheckRemoteMCPToolCatalogue checks a remote MCP proxy's tool overrides
// against the complete upstream tool catalogue (every tools/list page).
//
// It returns an error when an override's final name is also the name of an
// upstream tool that has no override, because both would then be exposed
// under the same name. Overrides whose source tool is not in the catalogue
// expose nothing; their source names are returned as missing and are not an
// error. See InspectRemoteMCPToolCatalogue for a report of every collision.
func CheckRemoteMCPToolCatalogue(ext *TykMCPServer, upstreamToolNames []string) (missingSources []string, err error) {
	missingSources, collisions := InspectRemoteMCPToolCatalogue(ext, upstreamToolNames)
	if len(collisions) > 0 {
		c := collisions[0]
		return nil, fmt.Errorf("%s: %q would be exposed by two tools: the upstream tool %q and the override of %q",
			ExtensionTykMCPServer, c.Name, c.Name, c.Source)
	}
	return missingSources, nil
}
