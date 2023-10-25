package middleware

import "github.com/TykTechnologies/tyk/apidef"

// Enabled returns whether middlewares are enabled or not.
func Enabled(defs ...apidef.MiddlewareDefinition) bool {
	for _, def := range defs {
		if !def.Disabled && def.Name != "" {
			return true
		}
	}

	return false
}
