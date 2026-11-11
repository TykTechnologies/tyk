package oas

import (
	"fmt"
)

// CheckRemoteMCPToolCatalogue checks a remote MCP proxy's tool overrides
// against the complete upstream tool catalogue (every tools/list page).
//
// It returns an error when an override's final name is also the name of an
// upstream tool that has no override, because both would then be exposed
// under the same name. Overrides whose source tool is not in the catalogue
// expose nothing; their source names are returned as missing and are not an
// error. Use ValidateRemoteMCPToolOverrides for the checks that need no
// catalogue.
func CheckRemoteMCPToolCatalogue(ext *TykMCPServer, upstreamToolNames []string) (missingSources []string, err error) {
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
				return nil, fmt.Errorf("%s: %q would be exposed by two tools: the upstream tool %q and the override of %q",
					ExtensionTykMCPServer, primitive.Name, primitive.Name, source)
			}
		}
	}
	return missingSources, nil
}
