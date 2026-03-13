package gateway

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
)

func TestOASPathSpecOrdering(t *testing.T) {
	const oasSpec = `{
		"openapi": "3.0.0",
		"info": {"title": "Path Ordering Test", "version": "1.0.0"},
		"paths": {
			"/users/{id}": {
				"get": {
					"operationId": "get_user"
				}
			},
			"/users/admin": {
				"get": {
					"operationId": "get_admin"
				}
			},
			"/users/{id}/posts": {
				"get": {
					"operationId": "get_user_posts"
				}
			},
			"/users/admin/posts": {
				"get": {
					"operationId": "get_admin_posts"
				}
			},
			"/a": {
				"get": {
					"operationId": "get_a"
				}
			},
			"/b": {
				"get": {
					"operationId": "get_b"
				}
			},
			"/users/{id}/posts/{postId}": {
				"get": {
					"operationId": "get_user_post"
				}
			}
		}
	}`

	oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
	assert.NoError(t, err)

	oasAPI := oas.OAS{T: *oasDoc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"get_user": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
					MockResponse:    &oas.MockResponse{Enabled: true},
				},
				"get_admin": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
					MockResponse:    &oas.MockResponse{Enabled: true},
				},
				"get_user_posts": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
					MockResponse:    &oas.MockResponse{Enabled: true},
				},
				"get_admin_posts": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
					MockResponse:    &oas.MockResponse{Enabled: true},
				},
				"get_a": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
					MockResponse:    &oas.MockResponse{Enabled: true},
				},
				"get_b": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
					MockResponse:    &oas.MockResponse{Enabled: true},
				},
				"get_user_post": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
					MockResponse:    &oas.MockResponse{Enabled: true},
				},
			},
		},
	})

	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			IsOAS: true,
		},
		OAS: oasAPI,
	}

	loader := APIDefinitionLoader{}
	conf := config.Config{}

	t.Run("ValidateRequest ordering", func(t *testing.T) {
		specs := loader.compileOASValidateRequestPathSpec(apiSpec, conf)
		assert.Len(t, specs, 7)

		// Expected order: longest first, then alphabetical
		expectedPaths := []string{
			"/users/{id}/posts/{postId}",
			"/users/admin/posts",
			"/users/{id}/posts",
			"/users/admin",
			"/users/{id}",
			"/a",
			"/b",
		}

		for i, expected := range expectedPaths {
			assert.Equal(t, expected, specs[i].OASPath, "Mismatch at index %d", i)
		}
	})

	t.Run("MockResponse ordering", func(t *testing.T) {
		specs := loader.compileOASMockResponsePathSpec(apiSpec, conf)
		assert.Len(t, specs, 7)

		// Expected order: longest first, then alphabetical
		expectedPaths := []string{
			"/users/{id}/posts/{postId}",
			"/users/admin/posts",
			"/users/{id}/posts",
			"/users/admin",
			"/users/{id}",
			"/a",
			"/b",
		}

		for i, expected := range expectedPaths {
			assert.Equal(t, expected, specs[i].OASPath, "Mismatch at index %d", i)
		}
	})
}
