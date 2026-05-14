package oas

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

// TestValidateForMCP covers the MCP-aware validation path. Empty config
// + IsMCP context resolves to mirror mode (no required static fields)
// where the OAS-level Validate would have rejected with
// "resource is required".
func TestValidateForMCP(t *testing.T) {
	mkOAS := func(prm *ProtectedResourceMetadata) OAS {
		o := OAS{T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "x", Version: "1.0"},
			Paths:   openapi3.NewPaths(),
		}}
		o.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				ListenPath:     ListenPath{Value: "/x/"},
				Authentication: &Authentication{ProtectedResourceMetadata: prm},
			},
		})
		return o
	}

	t.Run("MCP-mirror-by-default passes ValidateForMCP", func(t *testing.T) {
		o := mkOAS(&ProtectedResourceMetadata{Enabled: true})
		assert.NoError(t, o.ValidateForMCP(context.Background()))
	})

	t.Run("MCP-mirror-by-default fails plain Validate (non-MCP context)", func(t *testing.T) {
		o := mkOAS(&ProtectedResourceMetadata{Enabled: true})
		err := o.Validate(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "resource is required")
	})

	t.Run("explicit static config validates either way", func(t *testing.T) {
		o := mkOAS(&ProtectedResourceMetadata{
			Enabled:              true,
			Resource:             "https://api.example.com/x",
			AuthorizationServers: []string{"https://auth"},
		})
		assert.NoError(t, o.ValidateForMCP(context.Background()))
		assert.NoError(t, o.Validate(context.Background()))
	})

	t.Run("static-MCP without authorizationServers rejected", func(t *testing.T) {
		o := mkOAS(&ProtectedResourceMetadata{
			Enabled:  true,
			Resource: "https://api.example.com/x",
		})
		err := o.ValidateForMCP(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authorizationServers")
	})

	t.Run("disabled PRM passes both", func(t *testing.T) {
		o := mkOAS(&ProtectedResourceMetadata{Enabled: false})
		assert.NoError(t, o.ValidateForMCP(context.Background()))
		assert.NoError(t, o.Validate(context.Background()))
	})

	t.Run("no auth block at all passes both", func(t *testing.T) {
		o := OAS{T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "x", Version: "1.0"},
			Paths:   openapi3.NewPaths(),
		}}
		o.SetTykExtension(&XTykAPIGateway{
			Server: Server{ListenPath: ListenPath{Value: "/x/"}},
		})
		assert.NoError(t, o.ValidateForMCP(context.Background()))
		assert.NoError(t, o.Validate(context.Background()))
	})
}
