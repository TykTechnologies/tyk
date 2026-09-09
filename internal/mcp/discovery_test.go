package mcp

import "testing"

func TestIsHostRootDiscoveryPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"empty", "", false},
		{"prm exact with slash", "/.well-known/oauth-protected-resource", true},
		{"prm exact without slash", ".well-known/oauth-protected-resource", true},
		{"prm with resource suffix", "/.well-known/oauth-protected-resource/v1/mcp", true},
		{"as metadata", "/.well-known/oauth-authorization-server", true},
		{"oidc config", "/.well-known/openid-configuration", true},
		{"unrelated path", "/v1/mcp", false},
		{"nested but not well-known", "/api/.well-known/oauth-protected-resource", false},
		{"prefix collision", "/.well-known/oauth-protected-resource-other", false},
		{"random well-known", "/.well-known/jwks.json", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsHostRootDiscoveryPath(tc.path); got != tc.want {
				t.Fatalf("IsHostRootDiscoveryPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
