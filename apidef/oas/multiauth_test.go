package oas

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestMultiAuth_Fill(t *testing.T) {
	t.Run("single security requirement should disable MultiAuth", func(t *testing.T) {
		multiAuth := &MultiAuth{}
		security := openapi3.SecurityRequirements{
			{
				"apiKey": {},
			},
		}

		multiAuth.Fill(security)

		assert.False(t, multiAuth.Enabled)
		assert.Empty(t, multiAuth.Requirements)
	})

	t.Run("empty security requirements should disable MultiAuth", func(t *testing.T) {
		multiAuth := &MultiAuth{}
		security := openapi3.SecurityRequirements{}

		multiAuth.Fill(security)

		assert.False(t, multiAuth.Enabled)
		assert.Empty(t, multiAuth.Requirements)
	})

	t.Run("multiple security requirements should enable MultiAuth", func(t *testing.T) {
		multiAuth := &MultiAuth{}
		security := openapi3.SecurityRequirements{
			{
				"apiKey": {},
			},
			{
				"basicAuth": {},
			},
		}

		multiAuth.Fill(security)

		assert.True(t, multiAuth.Enabled)
		assert.Len(t, multiAuth.Requirements, 2)

		// Check first requirement
		req1 := multiAuth.Requirements[0]
		assert.Equal(t, "requirement_0", req1.Name)
		assert.Contains(t, req1.Schemes, "apiKey")
		assert.Equal(t, []string{}, req1.Schemes["apiKey"])

		// Check second requirement
		req2 := multiAuth.Requirements[1]
		assert.Equal(t, "requirement_1", req2.Name)
		assert.Contains(t, req2.Schemes, "basicAuth")
		assert.Equal(t, []string{}, req2.Schemes["basicAuth"])
	})

	t.Run("complex security requirements with AND logic within requirement", func(t *testing.T) {
		multiAuth := &MultiAuth{}
		security := openapi3.SecurityRequirements{
			{
				"apiKey":    {},
				"basicAuth": {},
			},
			{
				"jwt": {"read", "write"},
			},
		}

		multiAuth.Fill(security)

		assert.True(t, multiAuth.Enabled)
		assert.Len(t, multiAuth.Requirements, 2)

		// Check first requirement (AND logic: both apiKey AND basicAuth required)
		req1 := multiAuth.Requirements[0]
		assert.Equal(t, "requirement_0", req1.Name)
		assert.Len(t, req1.Schemes, 2)
		assert.Contains(t, req1.Schemes, "apiKey")
		assert.Contains(t, req1.Schemes, "basicAuth")

		// Check second requirement (JWT with scopes)
		req2 := multiAuth.Requirements[1]
		assert.Equal(t, "requirement_1", req2.Name)
		assert.Len(t, req2.Schemes, 1)
		assert.Contains(t, req2.Schemes, "jwt")
		assert.Equal(t, []string{"read", "write"}, req2.Schemes["jwt"])
	})
}

func TestOAS_importSingleAuthentication_MultiAuth(t *testing.T) {
	t.Run("should process single security requirement", func(t *testing.T) {
		oas := &OAS{
			T: openapi3.T{
				Security: openapi3.SecurityRequirements{
					{
						"apiKey": {},
					},
				},
				Components: &openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"apiKey": {
							Value: &openapi3.SecurityScheme{
								Type: "apiKey",
								In:   "header",
								Name: "Authorization",
							},
						},
					},
				},
			},
		}

		auth := &Authentication{Enabled: true} // Simulate what importAuthentication does
		err := oas.importSingleAuthentication(auth, true)

		assert.NoError(t, err)
		assert.True(t, auth.Enabled)
		assert.NotNil(t, auth.SecuritySchemes)
		assert.Contains(t, auth.SecuritySchemes, "apiKey")
	})
}

func TestOAS_importMultiAuthentication_MultiAuth(t *testing.T) {
	t.Run("should process multiple security requirements", func(t *testing.T) {
		oas := &OAS{
			T: openapi3.T{
				Security: openapi3.SecurityRequirements{
					{
						"apiKey": {},
					},
					{
						"basicAuth": {},
					},
				},
				Components: &openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"apiKey": {
							Value: &openapi3.SecurityScheme{
								Type: "apiKey",
								In:   "header",
								Name: "Authorization",
							},
						},
						"basicAuth": {
							Value: &openapi3.SecurityScheme{
								Type:   "http",
								Scheme: "basic",
							},
						},
					},
				},
			},
		}

		auth := &Authentication{}
		err := oas.importMultiAuthentication(auth, true)

		assert.NoError(t, err)
		assert.NotNil(t, auth.MultiAuth)
		assert.True(t, auth.MultiAuth.Enabled)
		assert.Len(t, auth.MultiAuth.Requirements, 2)

		// Check security schemes are imported
		assert.NotNil(t, auth.SecuritySchemes)
		assert.Contains(t, auth.SecuritySchemes, "apiKey")
		assert.Contains(t, auth.SecuritySchemes, "basicAuth")
	})

	t.Run("should handle duplicate schemes across requirements", func(t *testing.T) {
		oas := &OAS{
			T: openapi3.T{
				Security: openapi3.SecurityRequirements{
					{
						"apiKey": {},
					},
					{
						"apiKey":    {},
						"basicAuth": {},
					},
				},
				Components: &openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"apiKey": {
							Value: &openapi3.SecurityScheme{
								Type: "apiKey",
								In:   "header",
								Name: "Authorization",
							},
						},
						"basicAuth": {
							Value: &openapi3.SecurityScheme{
								Type:   "http",
								Scheme: "basic",
							},
						},
					},
				},
			},
		}

		auth := &Authentication{}
		err := oas.importMultiAuthentication(auth, true)

		assert.NoError(t, err)
		// Should import each scheme only once
		assert.Len(t, auth.SecuritySchemes, 2)
		assert.Contains(t, auth.SecuritySchemes, "apiKey")
		assert.Contains(t, auth.SecuritySchemes, "basicAuth")
	})
}

func TestOAS_importAuthentication_MultiAuth(t *testing.T) {
	t.Run("should use single auth for one security requirement", func(t *testing.T) {
		oas := &OAS{
			T: openapi3.T{
				Security: openapi3.SecurityRequirements{
					{
						"apiKey": {},
					},
				},
				Components: &openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"apiKey": {
							Value: &openapi3.SecurityScheme{
								Type: "apiKey",
								In:   "header",
								Name: "Authorization",
							},
						},
					},
				},
			},
		}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{},
		})

		err := oas.importAuthentication(true)

		assert.NoError(t, err)
		auth := oas.GetTykExtension().Server.Authentication
		assert.NotNil(t, auth)
		assert.True(t, auth.Enabled)
		assert.Nil(t, auth.MultiAuth) // Should not enable MultiAuth for single requirement
		assert.NotNil(t, auth.SecuritySchemes)
	})

	t.Run("should use multi auth for multiple security requirements", func(t *testing.T) {
		oas := &OAS{
			T: openapi3.T{
				Security: openapi3.SecurityRequirements{
					{
						"apiKey": {},
					},
					{
						"basicAuth": {},
					},
				},
				Components: &openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"apiKey": {
							Value: &openapi3.SecurityScheme{
								Type: "apiKey",
								In:   "header",
								Name: "Authorization",
							},
						},
						"basicAuth": {
							Value: &openapi3.SecurityScheme{
								Type:   "http",
								Scheme: "basic",
							},
						},
					},
				},
			},
		}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{},
		})

		err := oas.importAuthentication(true)

		assert.NoError(t, err)
		auth := oas.GetTykExtension().Server.Authentication
		assert.NotNil(t, auth)
		assert.True(t, auth.Enabled)
		assert.NotNil(t, auth.MultiAuth)
		assert.True(t, auth.MultiAuth.Enabled)
		assert.Len(t, auth.MultiAuth.Requirements, 2)
	})
}

func TestOAS_isAuthenticationEmpty(t *testing.T) {
	t.Run("should return true for nil authentication", func(t *testing.T) {
		oas := &OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{},
		})

		assert.True(t, oas.isAuthenticationEmpty())
	})

	t.Run("should return true for empty authentication", func(t *testing.T) {
		oas := &OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{},
			},
		})

		assert.True(t, oas.isAuthenticationEmpty())
	})

	t.Run("should return false when MultiAuth is configured", func(t *testing.T) {
		oas := &OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					MultiAuth: &MultiAuth{Enabled: true},
				},
			},
		})

		assert.False(t, oas.isAuthenticationEmpty())
	})

	t.Run("should return false when SecuritySchemes are configured", func(t *testing.T) {
		oas := &OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						"apiKey": &Token{Enabled: true},
					},
				},
			},
		})

		assert.False(t, oas.isAuthenticationEmpty())
	})
}
