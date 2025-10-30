package upstreamoauth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/model"
)

func TestProvider_Fill(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	provider := Provider{
		Logger:     logger,
		HeaderName: header.Authorization,
		AuthValue:  "Bearer test-token",
	}

	t.Run("sets header on empty request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)

		provider.Fill(req)

		assert.Equal(t, "Bearer test-token", req.Header.Get(header.Authorization))
	})

	t.Run("overwrites existing header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set(header.Authorization, "Bearer existing-token")

		provider.Fill(req)

		assert.Equal(t, "Bearer test-token", req.Header.Get(header.Authorization))
	})

	t.Run("custom header name", func(t *testing.T) {
		customProvider := Provider{
			Logger:     logger,
			HeaderName: "X-Custom-Auth",
			AuthValue:  "custom-value",
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)

		customProvider.Fill(req)

		assert.Equal(t, "custom-value", req.Header.Get("X-Custom-Auth"))
	})
}

func TestClientCredentialsOAuthProvider_getHeaderName(t *testing.T) {
	provider := &ClientCredentialsOAuthProvider{}

	tests := []struct {
		name     string
		spec     *Middleware
		expected string
	}{
		{
			name: "returns configured header name",
			spec: &Middleware{
				Spec: model.MergedAPI{
					APIDefinition: &apidef.APIDefinition{
						UpstreamAuth: apidef.UpstreamAuth{
							OAuth: apidef.UpstreamOAuth{
								ClientCredentials: apidef.ClientCredentials{
									Header: apidef.AuthSource{
										Name: "X-Custom-Auth",
									},
								},
							},
						},
					},
				},
			},
			expected: "X-Custom-Auth",
		},
		{
			name: "returns empty for no header config",
			spec: &Middleware{
				Spec: model.MergedAPI{
					APIDefinition: &apidef.APIDefinition{
						UpstreamAuth: apidef.UpstreamAuth{
							OAuth: apidef.UpstreamOAuth{
								ClientCredentials: apidef.ClientCredentials{
									Header: apidef.AuthSource{
										Name: "",
									},
								},
							},
						},
					},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.getHeaderName(tt.spec)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClientCredentialsOAuthProvider_headerEnabled(t *testing.T) {
	provider := &ClientCredentialsOAuthProvider{}

	tests := []struct {
		name     string
		spec     *Middleware
		expected bool
	}{
		{
			name: "header enabled",
			spec: &Middleware{
				Spec: model.MergedAPI{
					APIDefinition: &apidef.APIDefinition{
						UpstreamAuth: apidef.UpstreamAuth{
							OAuth: apidef.UpstreamOAuth{
								ClientCredentials: apidef.ClientCredentials{
									Header: apidef.AuthSource{
										Enabled: true,
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "header disabled",
			spec: &Middleware{
				Spec: model.MergedAPI{
					APIDefinition: &apidef.APIDefinition{
						UpstreamAuth: apidef.UpstreamAuth{
							OAuth: apidef.UpstreamOAuth{
								ClientCredentials: apidef.ClientCredentials{
									Header: apidef.AuthSource{
										Enabled: false,
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.headerEnabled(tt.spec)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPasswordOAuthProvider_getHeaderName(t *testing.T) {
	provider := &PasswordOAuthProvider{}

	spec := &Middleware{
		Spec: model.MergedAPI{
			APIDefinition: &apidef.APIDefinition{
				UpstreamAuth: apidef.UpstreamAuth{
					OAuth: apidef.UpstreamOAuth{
						PasswordAuthentication: apidef.PasswordAuthentication{
							Header: apidef.AuthSource{
								Name: "X-Password-Auth",
							},
						},
					},
				},
			},
		},
	}

	result := provider.getHeaderName(spec)
	assert.Equal(t, "X-Password-Auth", result)
}

func TestPasswordOAuthProvider_headerEnabled(t *testing.T) {
	provider := &PasswordOAuthProvider{}

	spec := &Middleware{
		Spec: model.MergedAPI{
			APIDefinition: &apidef.APIDefinition{
				UpstreamAuth: apidef.UpstreamAuth{
					OAuth: apidef.UpstreamOAuth{
						PasswordAuthentication: apidef.PasswordAuthentication{
							Header: apidef.AuthSource{
								Enabled: true,
							},
						},
					},
				},
			},
		},
	}

	result := provider.headerEnabled(spec)
	assert.True(t, result)
}

func TestNewOAuth2ClientCredentialsConfig(t *testing.T) {
	spec := &Middleware{
		Spec: model.MergedAPI{
			APIDefinition: &apidef.APIDefinition{
				UpstreamAuth: apidef.UpstreamAuth{
					OAuth: apidef.UpstreamOAuth{
						ClientCredentials: apidef.ClientCredentials{
							ClientAuthData: apidef.ClientAuthData{
								ClientID:     "test-client-id",
								ClientSecret: "test-client-secret",
							},
							TokenURL: "https://auth.example.com/token",
							Scopes:   []string{"read", "write"},
						},
					},
				},
			},
		},
	}

	config := newOAuth2ClientCredentialsConfig(spec)

	assert.Equal(t, "test-client-id", config.ClientID)
	assert.Equal(t, "test-client-secret", config.ClientSecret)
	assert.Equal(t, "https://auth.example.com/token", config.TokenURL)
	assert.Equal(t, []string{"read", "write"}, config.Scopes)
}

func TestNewOAuth2PasswordConfig(t *testing.T) {
	spec := &Middleware{
		Spec: model.MergedAPI{
			APIDefinition: &apidef.APIDefinition{
				UpstreamAuth: apidef.UpstreamAuth{
					OAuth: apidef.UpstreamOAuth{
						PasswordAuthentication: apidef.PasswordAuthentication{
							ClientAuthData: apidef.ClientAuthData{
								ClientID:     "test-client-id",
								ClientSecret: "test-client-secret",
							},
							TokenURL: "https://auth.example.com/token",
							Scopes:   []string{"read", "write"},
						},
					},
				},
			},
		},
	}

	config := newOAuth2PasswordConfig(spec)

	assert.Equal(t, "test-client-id", config.ClientID)
	assert.Equal(t, "test-client-secret", config.ClientSecret)
	assert.Equal(t, "https://auth.example.com/token", config.Endpoint.TokenURL)
	assert.Equal(t, []string{"read", "write"}, config.Scopes)
}

func TestGenerateClientCredentialsCacheKey(t *testing.T) {
	config := apidef.UpstreamOAuth{
		ClientCredentials: apidef.ClientCredentials{
			ClientAuthData: apidef.ClientAuthData{
				ClientID: "test-client-id",
			},
			TokenURL: "https://auth.example.com/token",
			Scopes:   []string{"read", "write"},
		},
	}
	apiId := "test-api-id"

	cacheKey := generateClientCredentialsCacheKey(config, apiId)

	// Verify the cache key is deterministic
	expectedKey := fmt.Sprintf(
		"cc-%s|%s|%s|%s",
		apiId,
		config.ClientCredentials.ClientID,
		config.ClientCredentials.TokenURL,
		strings.Join(config.ClientCredentials.Scopes, ","))

	hash := sha256.New()
	hash.Write([]byte(expectedKey))
	expectedHash := hex.EncodeToString(hash.Sum(nil))

	assert.Equal(t, expectedHash, cacheKey)
	assert.NotEmpty(t, cacheKey)

	// Verify the same inputs produce the same key
	cacheKey2 := generateClientCredentialsCacheKey(config, apiId)
	assert.Equal(t, cacheKey, cacheKey2)
}

func TestGeneratePasswordOAuthCacheKey(t *testing.T) {
	config := apidef.UpstreamOAuth{
		PasswordAuthentication: apidef.PasswordAuthentication{
			ClientAuthData: apidef.ClientAuthData{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
			Scopes: []string{"read", "write"},
		},
	}
	apiId := "test-api-id"

	cacheKey := generatePasswordOAuthCacheKey(config, apiId)

	// Verify the cache key is deterministic
	expectedKey := fmt.Sprintf(
		"pw-%s|%s|%s|%s",
		apiId,
		config.PasswordAuthentication.ClientID,
		config.PasswordAuthentication.ClientSecret,
		strings.Join(config.PasswordAuthentication.Scopes, ","))

	hash := sha256.New()
	hash.Write([]byte(expectedKey))
	expectedHash := hex.EncodeToString(hash.Sum(nil))

	assert.Equal(t, expectedHash, cacheKey)
	assert.NotEmpty(t, cacheKey)

	// Verify the same inputs produce the same key
	cacheKey2 := generatePasswordOAuthCacheKey(config, apiId)
	assert.Equal(t, cacheKey, cacheKey2)
}

func TestGenerateCacheKeys_Different(t *testing.T) {
	config1 := apidef.UpstreamOAuth{
		ClientCredentials: apidef.ClientCredentials{
			ClientAuthData: apidef.ClientAuthData{
				ClientID: "client1",
			},
			TokenURL: "https://auth1.example.com/token",
			Scopes:   []string{"read"},
		},
	}

	config2 := apidef.UpstreamOAuth{
		ClientCredentials: apidef.ClientCredentials{
			ClientAuthData: apidef.ClientAuthData{
				ClientID: "client2",
			},
			TokenURL: "https://auth2.example.com/token",
			Scopes:   []string{"write"},
		},
	}

	key1 := generateClientCredentialsCacheKey(config1, "api1")
	key2 := generateClientCredentialsCacheKey(config2, "api2")

	assert.NotEqual(t, key1, key2, "Different configurations should produce different cache keys")
}

func TestHandleOAuthError(t *testing.T) {
	// Setup mock middleware
	mw := &Middleware{
		Base: &mockBaseMiddleware{},
		Spec: model.MergedAPI{
			APIDefinition: &apidef.APIDefinition{
				APIID: "test-api",
			},
		},
	}

	// Setup expectations
	mockBase := mw.Base.(*mockBaseMiddleware)
	mockBase.On("FireEvent", mock.AnythingOfType("event.Event"), mock.AnythingOfType("upstreamoauth.EventUpstreamOAuthMeta"))

	req := httptest.NewRequest("GET", "http://example.com", nil)
	testError := fmt.Errorf("OAuth error occurred")

	result, err := handleOAuthError(req, mw, testError)

	assert.Error(t, err)
	assert.Equal(t, testError, err)
	assert.Empty(t, result)

	// Verify event was fired
	mockBase.AssertCalled(t, "FireEvent", mock.AnythingOfType("event.Event"), mock.AnythingOfType("upstreamoauth.EventUpstreamOAuthMeta"))
}

func TestEventUpstreamOAuthMeta(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)

	meta := EventUpstreamOAuthMeta{
		EventMetaDefault: model.NewEventMetaDefault(req, "Test message"),
		APIID:            "test-api-id",
	}

	assert.Equal(t, "test-api-id", meta.APIID)
	assert.NotNil(t, meta.EventMetaDefault)
}
