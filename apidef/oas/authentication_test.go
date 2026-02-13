package oas

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestAuthentication(t *testing.T) {
	var emptyAuthentication Authentication

	var convertedAPI apidef.APIDefinition
	emptyAuthentication.ExtractTo(&convertedAPI)

	var resultAuthentication Authentication
	resultAuthentication.Fill(convertedAPI)

	assert.Equal(t, emptyAuthentication, resultAuthentication)
}

func TestScopes(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		var emptyScopes Scopes

		scopeClaim := apidef.ScopeClaim{}
		emptyScopes.ExtractTo(&scopeClaim)

		var resultScopes Scopes
		resultScopes.Fill(&scopeClaim)

		assert.Equal(t, emptyScopes, resultScopes)
	})
	t.Run("fill scope claim", func(t *testing.T) {
		var emptyScopes Scopes

		scopeClaim := apidef.ScopeClaim{
			ScopeClaimName: "test",
		}

		emptyScopes.Fill(&scopeClaim)

		assert.Equal(t, emptyScopes.Claims, []string{scopeClaim.ScopeClaimName})
	})

	t.Run("extract scope claim", func(t *testing.T) {
		var emptydefScopeClaim apidef.ScopeClaim

		scope := Scopes{
			Claims:    []string{"test", "second"},
			ClaimName: "test",
		}

		scope.ExtractTo(&emptydefScopeClaim)
		assert.Equal(t, emptydefScopeClaim.ScopeClaimName, "test")
	})

}

func TestAuthSources(t *testing.T) {
	var emptyAuthSources AuthSources

	var convertedAuthConfig apidef.AuthConfig
	emptyAuthSources.ExtractTo(&convertedAuthConfig)

	var resultAuthSources AuthSources
	resultAuthSources.Fill(convertedAuthConfig)

	assert.Equal(t, emptyAuthSources, resultAuthSources)
}

func TestAuthSource(t *testing.T) {
	t.Run("param", func(t *testing.T) {
		var emptyParamSource AuthSource

		var convertedAuthConfig apidef.AuthConfig
		emptyParamSource.ExtractTo(&convertedAuthConfig.UseParam, &convertedAuthConfig.ParamName)

		var resultParamSource AuthSource
		resultParamSource.Fill(convertedAuthConfig.UseParam, convertedAuthConfig.ParamName)

		assert.Equal(t, emptyParamSource, resultParamSource)
	})

	t.Run("cookie", func(t *testing.T) {
		var emptyCookieSource AuthSource

		var convertedAuthConfig apidef.AuthConfig
		emptyCookieSource.ExtractTo(&convertedAuthConfig.UseCookie, &convertedAuthConfig.CookieName)

		var resultCookieSource AuthSource
		resultCookieSource.Fill(convertedAuthConfig.UseCookie, convertedAuthConfig.CookieName)

		assert.Equal(t, emptyCookieSource, resultCookieSource)
	})
}

func TestSignature(t *testing.T) {
	var emptySignature Signature

	var convertedAuthConfig apidef.AuthConfig
	emptySignature.ExtractTo(&convertedAuthConfig)

	var resultSignature Signature
	resultSignature.Fill(convertedAuthConfig)

	assert.Equal(t, emptySignature, resultSignature)
}

func TestHMAC(t *testing.T) {
	var emptyHMAC HMAC

	var convertedAPI apidef.APIDefinition
	emptyHMAC.ExtractTo(&convertedAPI)

	var resultHMAC HMAC
	resultHMAC.Fill(convertedAPI)

	assert.Equal(t, emptyHMAC, resultHMAC)
}

func TestOIDC(t *testing.T) {
	var emptyOIDC OIDC

	var convertedAPI apidef.APIDefinition
	emptyOIDC.ExtractTo(&convertedAPI)

	var resultOIDC OIDC
	emptyOIDC.Fill(convertedAPI)

	assert.Equal(t, emptyOIDC, resultOIDC)

	t.Run("providers", func(t *testing.T) {
		var api apidef.APIDefinition
		api.OpenIDOptions.Providers = []apidef.OIDProviderConfig{{Issuer: "1234"}}

		var oas OAS
		xTyk := &XTykAPIGateway{Server: Server{
			Authentication: &Authentication{
				OIDC: &OIDC{
					Providers: []Provider{{Issuer: "5678"}},
				},
			},
		}}

		oas.SetTykExtension(xTyk)
		oas.ExtractTo(&api)

		assert.Len(t, api.OpenIDOptions.Providers, 1)
		assert.Equal(t, "5678", api.OpenIDOptions.Providers[0].Issuer)
	})
}

func TestCertificateAuthPrecedence(t *testing.T) {
	t.Run("certificate auth field exists", func(t *testing.T) {
		const securityName = "custom"
		var trueVal = true
		oas := OAS{
			T: openapi3.T{
				Components: &openapi3.Components{
					SecuritySchemes: openapi3.SecuritySchemes{
						securityName: {
							Value: &openapi3.SecurityScheme{
								Type: typeAPIKey,
								Name: "x-query",
								In:   query,
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						securityName: []string{},
					},
				},
				Extensions: map[string]interface{}{
					ExtensionTykAPIGateway: &XTykAPIGateway{
						Server: Server{
							Authentication: &Authentication{
								SecuritySchemes: SecuritySchemes{
									securityName: &Token{
										Enabled:                 &trueVal,
										EnableClientCertificate: true,
									},
								},
								CertificateAuth: CertificateAuth{
									Enabled: false,
								},
							},
						},
					},
				},
			},
		}

		var apiDef apidef.APIDefinition
		oas.ExtractTo(&apiDef)

		assert.False(t, apiDef.AuthConfigs[apidef.AuthTokenType].UseCertificate)
	})

	t.Run("certificate auth field does not exist", func(t *testing.T) {
		const securityName = "custom"
		var trueVal = true
		oas := OAS{
			T: openapi3.T{
				Components: &openapi3.Components{
					SecuritySchemes: openapi3.SecuritySchemes{
						securityName: {
							Value: &openapi3.SecurityScheme{
								Type: typeAPIKey,
								Name: "x-query",
								In:   query,
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						securityName: []string{},
					},
				},
				Extensions: map[string]interface{}{
					ExtensionTykAPIGateway: &XTykAPIGateway{
						Server: Server{
							Authentication: &Authentication{
								SecuritySchemes: SecuritySchemes{
									securityName: &Token{
										Enabled:                 &trueVal,
										EnableClientCertificate: true,
									},
								},
							},
						},
					},
				},
			},
		}

		var apiDef apidef.APIDefinition
		oas.ExtractTo(&apiDef)

		assert.False(t, apiDef.AuthConfigs[apidef.AuthTokenType].UseCertificate)
	})
}

func TestCertificateAuth(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var emptyCertificateAuth CertificateAuth
		var convertedAPI apidef.APIDefinition
		var resultCertificateAuth CertificateAuth

		convertedAPI.SetDisabledFlags()
		emptyCertificateAuth.ExtractTo(&convertedAPI)
		resultCertificateAuth.Fill(convertedAPI)

		assert.Equal(t, emptyCertificateAuth, resultCertificateAuth)
		assert.Falsef(t, convertedAPI.AuthConfigs[apidef.AuthTokenType].UseCertificate, "AuthTokenType should not be set to use certificate auth")
	})

	t.Run("filled", func(t *testing.T) {
		certAuth := CertificateAuth{
			Enabled: true,
		}

		var convertedAPI apidef.APIDefinition
		var resultCertificateAuth CertificateAuth

		certAuth.ExtractTo(&convertedAPI)
		assert.True(t, convertedAPI.AuthConfigs[apidef.AuthTokenType].UseCertificate)

		resultCertificateAuth.Fill(convertedAPI)

		assert.Equal(t, certAuth, resultCertificateAuth)
	})
}

func TestKeyRetentionPeriod(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var emptyCustomKeyLifetime CustomKeyLifetime
		var convertedAPI apidef.APIDefinition
		var resultCustomKeyLifetime CustomKeyLifetime

		convertedAPI.SetDisabledFlags()
		emptyCustomKeyLifetime.ExtractTo(&convertedAPI)
		resultCustomKeyLifetime.Fill(convertedAPI)

		assert.Equal(t, int64(0), convertedAPI.SessionLifetime)

		assert.Equal(t, emptyCustomKeyLifetime, resultCustomKeyLifetime)
	})

	t.Run("filled", func(t *testing.T) {
		keyRetentionPeriod := CustomKeyLifetime{
			Enabled:         true,
			Value:           ReadableDuration(5 * time.Minute),
			RespectValidity: true,
		}
		var convertedAPI apidef.APIDefinition
		var resultKeyRetentionPeriod CustomKeyLifetime

		keyRetentionPeriod.ExtractTo(&convertedAPI)

		assert.Equal(t, int64(300), convertedAPI.SessionLifetime)
		assert.True(t, convertedAPI.SessionLifetimeRespectsKeyExpiration)

		resultKeyRetentionPeriod.Fill(convertedAPI)

		assert.Equal(t, keyRetentionPeriod, resultKeyRetentionPeriod)
	})
}

func TestCustomPlugin(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var emptyCustomPlugin CustomPluginAuthentication

		var convertedAPI apidef.APIDefinition
		convertedAPI.SetDisabledFlags()
		emptyCustomPlugin.ExtractTo(&convertedAPI)

		var resultCustomPlugin CustomPluginAuthentication
		resultCustomPlugin.Fill(convertedAPI)

		assert.Equal(t, emptyCustomPlugin, resultCustomPlugin)
	})

	t.Run("values", func(t *testing.T) {
		t.Run("goplugin", func(t *testing.T) {
			expectedCustomPluginAuth := CustomPluginAuthentication{
				Enabled: true,
				Config: &AuthenticationPlugin{
					Enabled:        true,
					FunctionName:   "Auth",
					Path:           "/path/to/plugin",
					RequireSession: true,
				},
			}

			var convertedAPI apidef.APIDefinition
			convertedAPI.SetDisabledFlags()
			expectedCustomPluginAuth.ExtractTo(&convertedAPI)

			var actualCustomPluginAuth CustomPluginAuthentication
			actualCustomPluginAuth.Fill(convertedAPI)

			assert.Equal(t, expectedCustomPluginAuth, actualCustomPluginAuth)
			assert.Empty(t, actualCustomPluginAuth.AuthSources)
		})

		t.Run("coprocess", func(t *testing.T) {
			expectedCustomPluginAuth := CustomPluginAuthentication{
				Enabled: true,
				Config: &AuthenticationPlugin{
					Enabled:        true,
					FunctionName:   "Auth",
					Path:           "/path/to/plugin",
					RequireSession: true,
				},
				AuthSources: AuthSources{
					Header: &AuthSource{
						Enabled: true,
						Name:    "Authorization",
					},
				},
			}

			var convertedAPI apidef.APIDefinition
			convertedAPI.SetDisabledFlags()
			expectedCustomPluginAuth.ExtractTo(&convertedAPI)

			var actualCustomPluginAuth CustomPluginAuthentication
			actualCustomPluginAuth.Fill(convertedAPI)

			assert.Equal(t, expectedCustomPluginAuth, actualCustomPluginAuth)
			assert.NotEmpty(t, actualCustomPluginAuth.AuthSources)
		})
	})
}

func TestIDExtractorConfig(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var emptyIDExtractorConfig IDExtractorConfig

		var convertedAPI apidef.APIDefinition
		convertedAPI.SetDisabledFlags()
		emptyIDExtractorConfig.ExtractTo(&convertedAPI)

		var resultIDExtractorConfig IDExtractorConfig
		resultIDExtractorConfig.Fill(convertedAPI)

		assert.Equal(t, emptyIDExtractorConfig, resultIDExtractorConfig)
	})

	t.Run("values", func(t *testing.T) {
		t.Parallel()

		expectedIDExtractorConfig := IDExtractorConfig{
			HeaderName:       "Authorization",
			FormParamName:    "Authorization",
			RegexpMatchIndex: 1,
			Regexp:           "regexp",
			XPathExp:         "xpathexp",
		}

		var convertedAPI apidef.APIDefinition
		convertedAPI.SetDisabledFlags()
		expectedIDExtractorConfig.ExtractTo(&convertedAPI)

		var actualIDExtractorConfig IDExtractorConfig
		actualIDExtractorConfig.Fill(convertedAPI)

		assert.Equal(t, expectedIDExtractorConfig, actualIDExtractorConfig)
	})
}

func TestIDExtractor(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var emptyIDExtractor IDExtractor

		var convertedAPI apidef.APIDefinition
		convertedAPI.SetDisabledFlags()
		emptyIDExtractor.ExtractTo(&convertedAPI)

		var resultIDExtractor IDExtractor
		resultIDExtractor.Fill(convertedAPI)

		assert.Equal(t, emptyIDExtractor, resultIDExtractor)
	})

	t.Run("values", func(t *testing.T) {
		t.Parallel()

		expectedIDExtractor := IDExtractor{
			Enabled: true,
			Source:  apidef.HeaderSource,
			With:    apidef.ValueExtractor,
			Config: &IDExtractorConfig{
				HeaderName:       "Authorization",
				FormParamName:    "Authorization",
				RegexpMatchIndex: 1,
				Regexp:           "regexp",
				XPathExp:         "xpathexp",
			},
		}

		var convertedAPI apidef.APIDefinition
		convertedAPI.SetDisabledFlags()
		expectedIDExtractor.ExtractTo(&convertedAPI)

		var actualIDExtractor IDExtractor
		actualIDExtractor.Fill(convertedAPI)

		assert.Equal(t, expectedIDExtractor, actualIDExtractor)
	})
}

func TestSecurityProcessingMode(t *testing.T) {
	t.Run("DefaultValues", func(t *testing.T) {
		testCases := []struct {
			name     string
			input    *Authentication
			expected string
		}{
			{
				name:     "empty field stays empty",
				input:    &Authentication{},
				expected: "",
			},
			{
				name: "empty string stays empty",
				input: &Authentication{
					SecurityProcessingMode: "",
				},
				expected: "",
			},
			{
				name: "explicit legacy",
				input: &Authentication{
					SecurityProcessingMode: SecurityProcessingModeLegacy,
				},
				expected: "legacy",
			},
			{
				name: "explicit compliant",
				input: &Authentication{
					SecurityProcessingMode: SecurityProcessingModeCompliant,
				},
				expected: "compliant",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				var api apidef.APIDefinition
				tc.input.ExtractTo(&api)
				assert.Equal(t, tc.expected, tc.input.SecurityProcessingMode)
			})
		}
	})

	t.Run("Validation", func(t *testing.T) {
		testCases := []struct {
			name          string
			mode          string
			shouldBeValid bool
		}{
			{"valid legacy", "legacy", true},
			{"valid compliant", "compliant", true},
			{"empty string", "", true},
			{"invalid mode", "invalid", false},
			{"numeric value", "123", false},
			{"mixed case", "Legacy", false},
			{"with spaces", "legacy ", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				isValid := ValidateSecurityProcessingMode(tc.mode)
				assert.Equal(t, tc.shouldBeValid, isValid)
			})
		}
	})

	t.Run("ExtractToWithValidation", func(t *testing.T) {
		testCases := []struct {
			name     string
			input    string
			expected string
		}{
			{"empty stays empty", "", ""},
			{"legacy stays legacy", "legacy", "legacy"},
			{"compliant stays compliant", "compliant", "compliant"},
			{"invalid defaults to legacy", "invalid", "legacy"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				auth := &Authentication{
					SecurityProcessingMode: tc.input,
				}
				var api apidef.APIDefinition
				auth.ExtractTo(&api)
				assert.Equal(t, tc.input, auth.SecurityProcessingMode)
			})
		}
	})

	t.Run("FillFromAPIDefinition", func(t *testing.T) {
		// Test that SecurityProcessingMode is OAS-only and NOT filled from APIDefinition
		t.Run("preserves existing OAS value", func(t *testing.T) {
			api := apidef.APIDefinition{}

			auth := &Authentication{
				SecurityProcessingMode: SecurityProcessingModeCompliant, // Pre-existing OAS value
			}
			auth.Fill(api)

			// Should preserve the OAS value, not overwrite from APIDefinition
			assert.Equal(t, SecurityProcessingModeCompliant, auth.SecurityProcessingMode)
		})

		t.Run("empty stays empty if not set", func(t *testing.T) {
			api := apidef.APIDefinition{}

			auth := &Authentication{}
			auth.Fill(api)

			// Should remain empty since it's not filled from APIDefinition
			assert.Equal(t, "", auth.SecurityProcessingMode)
		})

		t.Run("legacy value preserved", func(t *testing.T) {
			api := apidef.APIDefinition{}

			auth := &Authentication{
				SecurityProcessingMode: SecurityProcessingModeLegacy, // Pre-existing OAS value
			}
			auth.Fill(api)

			// Should preserve the OAS value
			assert.Equal(t, SecurityProcessingModeLegacy, auth.SecurityProcessingMode)
		})
	})

	t.Run("GetDefaultSecurityProcessingMode", func(t *testing.T) {
		assert.Equal(t, SecurityProcessingModeLegacy, GetDefaultSecurityProcessingMode())
	})
}

func TestVendorExtensionSecurity(t *testing.T) {
	t.Run("Security array field", func(t *testing.T) {
		auth := &Authentication{
			Security: [][]string{
				{"hmac"},
				{"custom"},
				{"hmac", "jwt"},
			},
		}

		var api apidef.APIDefinition
		auth.ExtractTo(&api)

		auth2 := &Authentication{}
		auth2.Fill(api)

		assert.Nil(t, auth2.Security)
	})
}

func TestProtectedResourceMetadata_Validate(t *testing.T) {
	t.Parallel()

	t.Run("nil PRM returns no error", func(t *testing.T) {
		t.Parallel()
		var prm *ProtectedResourceMetadata
		assert.NoError(t, prm.Validate(false))
		assert.NoError(t, prm.Validate(true))
	})

	t.Run("disabled PRM returns no error", func(t *testing.T) {
		t.Parallel()
		prm := &ProtectedResourceMetadata{Enabled: false}
		assert.NoError(t, prm.Validate(false))
		assert.NoError(t, prm.Validate(true))
	})

	t.Run("enabled without resource returns error", func(t *testing.T) {
		t.Parallel()
		prm := &ProtectedResourceMetadata{
			Enabled:              true,
			AuthorizationServers: []string{"https://auth.example.com"},
		}
		err := prm.Validate(false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "resource is required")
	})

	t.Run("MCP without authorizationServers returns error", func(t *testing.T) {
		t.Parallel()
		prm := &ProtectedResourceMetadata{
			Enabled:  true,
			Resource: "https://api.example.com",
		}
		err := prm.Validate(true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authorizationServers")
	})

	t.Run("non-MCP without authorizationServers returns no error", func(t *testing.T) {
		t.Parallel()
		prm := &ProtectedResourceMetadata{
			Enabled:  true,
			Resource: "https://api.example.com",
		}
		assert.NoError(t, prm.Validate(false))
	})

	t.Run("valid MCP configuration", func(t *testing.T) {
		t.Parallel()
		prm := &ProtectedResourceMetadata{
			Enabled:              true,
			Resource:             "https://api.example.com",
			AuthorizationServers: []string{"https://auth.example.com"},
			ScopesSupported:      []string{"read", "write"},
		}
		assert.NoError(t, prm.Validate(true))
	})

	t.Run("valid non-MCP configuration", func(t *testing.T) {
		t.Parallel()
		prm := &ProtectedResourceMetadata{
			Enabled:              true,
			Resource:             "https://api.example.com",
			AuthorizationServers: []string{"https://auth.example.com"},
		}
		assert.NoError(t, prm.Validate(false))
	})
}

func TestProtectedResourceMetadata_GetWellKnownPath(t *testing.T) {
	t.Parallel()

	t.Run("nil returns default", func(t *testing.T) {
		t.Parallel()
		var prm *ProtectedResourceMetadata
		assert.Equal(t, DefaultPRMWellKnownPath, prm.GetWellKnownPath())
	})

	t.Run("empty path returns default", func(t *testing.T) {
		t.Parallel()
		prm := &ProtectedResourceMetadata{}
		assert.Equal(t, DefaultPRMWellKnownPath, prm.GetWellKnownPath())
	})

	t.Run("custom path returned", func(t *testing.T) {
		t.Parallel()
		prm := &ProtectedResourceMetadata{WellKnownPath: ".well-known/custom"}
		assert.Equal(t, ".well-known/custom", prm.GetWellKnownPath())
	})
}

func TestProtectedResourceMetadata_JSON(t *testing.T) {
	t.Parallel()

	t.Run("round-trip serialization", func(t *testing.T) {
		t.Parallel()
		prm := &ProtectedResourceMetadata{
			Enabled:              true,
			WellKnownPath:        ".well-known/oauth-protected-resource",
			Resource:             "https://api.example.com",
			AuthorizationServers: []string{"https://auth.example.com"},
			ScopesSupported:      []string{"read", "write"},
		}

		data, err := json.Marshal(prm)
		assert.NoError(t, err)

		var decoded ProtectedResourceMetadata
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)
		assert.Equal(t, *prm, decoded)
	})

	t.Run("ShouldOmit behavior", func(t *testing.T) {
		t.Parallel()
		prm := &ProtectedResourceMetadata{}
		assert.True(t, ShouldOmit(prm))

		prm.Enabled = true
		assert.False(t, ShouldOmit(prm))
	})

	t.Run("omitempty fields excluded when empty", func(t *testing.T) {
		t.Parallel()
		prm := &ProtectedResourceMetadata{Enabled: true}

		data, err := json.Marshal(prm)
		assert.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		assert.NoError(t, err)
		assert.Contains(t, raw, "enabled")
		assert.NotContains(t, raw, "wellKnownPath")
		assert.NotContains(t, raw, "resource")
		assert.NotContains(t, raw, "authorizationServers")
		assert.NotContains(t, raw, "scopesSupported")
	})
}
