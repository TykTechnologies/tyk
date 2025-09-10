package oas

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestAuthentication(t *testing.T) {
	var emptyAuthentication Authentication

	var convertedAPI apidef.APIDefinition
	emptyAuthentication.ExtractTo(&convertedAPI)

	var resultAuthentication Authentication
	resultAuthentication.Fill(convertedAPI)

	// Set expected default for SecurityProcessingMode
	emptyAuthentication.SecurityProcessingMode = "legacy"
	
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
				name:     "nil field defaults to legacy",
				input:    &Authentication{},
				expected: "legacy",
			},
			{
				name: "empty string defaults to legacy",
				input: &Authentication{
					SecurityProcessingMode: "",
				},
				expected: "legacy",
			},
			{
				name: "explicit legacy",
				input: &Authentication{
					SecurityProcessingMode: "legacy",
				},
				expected: "legacy",
			},
			{
				name: "explicit compliant",
				input: &Authentication{
					SecurityProcessingMode: "compliant",
				},
				expected: "compliant",
			},
		}
		
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				var api apidef.APIDefinition
				tc.input.ExtractTo(&api)
				assert.Equal(t, tc.expected, api.SecurityProcessingMode)
			})
		}
	})
	
	t.Run("Validation", func(t *testing.T) {
		testCases := []struct {
			name        string
			mode        string
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
			{"empty defaults to legacy", "", "legacy"},
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
				assert.Equal(t, tc.expected, api.SecurityProcessingMode)
			})
		}
	})
	
	t.Run("FillWithDefault", func(t *testing.T) {
		// Test that Fill properly sets default when API has empty mode
		api := apidef.APIDefinition{
			SecurityProcessingMode: "",
		}
		
		auth := &Authentication{}
		auth.Fill(api)
		
		assert.Equal(t, "legacy", auth.SecurityProcessingMode)
	})
	
	t.Run("GetDefaultSecurityProcessingMode", func(t *testing.T) {
		assert.Equal(t, "legacy", GetDefaultSecurityProcessingMode())
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
		
		// The Security field should not be extracted to APIDefinition
		// It's only stored in the OAS extension
		
		auth2 := &Authentication{}
		auth2.Fill(api)
		
		// Security field is not filled from APIDefinition
		// It only exists in OAS vendor extension
		assert.Nil(t, auth2.Security)
	})
}
