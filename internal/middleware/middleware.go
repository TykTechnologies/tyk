package middleware

import "github.com/TykTechnologies/tyk/apidef"

func Enabled(defs ...apidef.MiddlewareDefinition) bool {
	for _, def := range defs {
		// gRPC coprocess won't return true since def.path would be empty.
		if !def.Disabled && def.Path != "" && def.Name != "" {
			return true
		}
	}

	return false
}
