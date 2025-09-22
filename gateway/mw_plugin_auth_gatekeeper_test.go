package gateway

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPluginAuthGatekeeperMiddleware_EnabledForSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     *APISpec
		expected bool
	}{
		{
			name: "Custom plugin auth disabled",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CustomPluginAuthEnabled: false,
				},
			},
			expected: false,
		},
		{
			name: "Custom plugin auth disabled with full configuration for auth plugin",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CustomPluginAuthEnabled: false,
					CustomMiddleware: apidef.MiddlewareSection{
						Driver: apidef.MiddlewareDriver("goplugin"),
						AuthCheck: apidef.MiddlewareDefinition{
							Disabled:       false,
							Name:           "TestAuthPlugin",
							Path:           "/test/path/plugin.so",
							RequireSession: false,
							RawBodyOnly:    false,
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Custom plugin auth enabled but no driver provided",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CustomPluginAuthEnabled: true,
					CustomMiddleware:        apidef.MiddlewareSection{Driver: apidef.MiddlewareDriver("")},
				},
			},
			expected: true,
		},
		{
			name: "Custom plugin auth enabled, driver provided but no auth plugin configured",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CustomPluginAuthEnabled: true,
					CustomMiddleware:        apidef.MiddlewareSection{Driver: apidef.MiddlewareDriver("goplugin")},
				},
			},
			expected: true,
		},
		{
			name: "Custom plugin auth enabled, driver provided but no path to auth plugin provided",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CustomPluginAuthEnabled: true,
					CustomMiddleware: apidef.MiddlewareSection{
						Driver: apidef.MiddlewareDriver("goplugin"),
						AuthCheck: apidef.MiddlewareDefinition{
							Disabled:       false,
							Name:           "TestAuthPlugin",
							Path:           "",
							RequireSession: false,
							RawBodyOnly:    false,
						},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &PluginAuthGatekeeperMiddleware{BaseMiddleware: &BaseMiddleware{Spec: tt.spec}}

			assert.Equal(t, tt.expected, mw.EnabledForSpec())
		})
	}
}
