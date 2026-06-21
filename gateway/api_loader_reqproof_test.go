package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: STK-REQ-074, SYS-REQ-162, SW-REQ-149
// STK-REQ-074:STK-REQ-074-AC-01:acceptance
// SW-REQ-149:nominal:nominal
// SW-REQ-149:boundary:nominal
// SW-REQ-149:boundary:boundary
// SW-REQ-149:determinism:nominal
// SYS-REQ-162:determinism:nominal
func TestGatewayAPILoaderLocalHelpers(t *testing.T) {
	t.Run("domain path key", func(t *testing.T) {
		tests := []struct {
			name       string
			host       string
			listenPath string
			want       string
		}{
			{name: "host and slash path", host: "api.example.com", listenPath: "/v1/", want: "api.example.com/v1/"},
			{name: "empty host", listenPath: "/public/", want: "/public/"},
			{name: "empty listen path", host: "api.example.com", want: "api.example.com"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, generateDomainPath(tt.host, tt.listenPath))
			})
		}
	})

	t.Run("count APIs by listen hash", func(t *testing.T) {
		specs := []*APISpec{
			apiLoaderHelperSpec("first", "api.example.com", false, "/v1/"),
			apiLoaderHelperSpec("second", "api.example.com", false, "/v1/"),
			apiLoaderHelperSpec("third", "api.example.com", false, "/v2/"),
			apiLoaderHelperSpec("domain disabled", "ignored.example.com", true, "/v1/"),
			apiLoaderHelperSpec("no host", "", false, "/v1/"),
		}

		assert.Equal(t, map[string]int{
			"api.example.com/v1/": 2,
			"api.example.com/v2/": 1,
			"/v1/":                2,
		}, countApisByListenHash(specs))
	})

	t.Run("prefix middleware function paths", func(t *testing.T) {
		functions := []apidef.MiddlewareDefinition{
			{Name: "pre", Path: "middleware/pre.js"},
			{Name: "post", Path: "middleware/post.js"},
			{Name: "empty"},
		}

		fixFuncPath("/opt/tyk", functions)

		assert.Equal(t, []apidef.MiddlewareDefinition{
			{Name: "pre", Path: "/opt/tyk/middleware/pre.js"},
			{Name: "post", Path: "/opt/tyk/middleware/post.js"},
			{Name: "empty", Path: "/opt/tyk"},
		}, functions)
	})
}

func apiLoaderHelperSpec(name, domain string, domainDisabled bool, listenPath string) *APISpec {
	return &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Name:           name,
			Domain:         domain,
			DomainDisabled: domainDisabled,
			Proxy: apidef.ProxyConfig{
				ListenPath: listenPath,
			},
		},
	}
}
