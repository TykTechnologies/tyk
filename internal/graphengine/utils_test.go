package graphengine

import (
	"context"
	"net/http"
	"testing"

	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
)

func testLogger() abstractlogger.Logger {
	return abstractlogger.NewLogrusLogger(logrus.New(), abstractlogger.InfoLevel)
}

func TestAdditionalUpstreamHeaders_PropagateAuthHeaders(t *testing.T) {
	t.Run("should propagate default Authorization header when StripAuthData is false for UDG", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set(header.Authorization, "Bearer token123")

		apiDef := &apidef.APIDefinition{
			StripAuthData:   false,
			UseStandardAuth: true,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Equal(t, "Bearer token123", result.Get(header.Authorization))
	})

	t.Run("should propagate default Authorization header when StripAuthData is false for supergraph", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set(header.Authorization, "Bearer token123")

		apiDef := &apidef.APIDefinition{
			StripAuthData:   false,
			UseStandardAuth: true,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeSupergraph

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Equal(t, "Bearer token123", result.Get(header.Authorization))
	})

	t.Run("should not propagate auth headers when StripAuthData is true", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set(header.Authorization, "Bearer token123")

		apiDef := &apidef.APIDefinition{
			StripAuthData:   true,
			UseStandardAuth: true,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Empty(t, result.Get(header.Authorization))
	})

	t.Run("should propagate auth headers for proxy-only mode (needed for subscriptions)", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set(header.Authorization, "Bearer token123")

		apiDef := &apidef.APIDefinition{
			StripAuthData: false,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Equal(t, "Bearer token123", result.Get(header.Authorization),
			"proxy-only subscriptions bypass transport so auth must be propagated here")
	})

	t.Run("should propagate auth headers for subgraph mode", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set(header.Authorization, "Bearer token123")

		apiDef := &apidef.APIDefinition{
			StripAuthData: false,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeSubgraph

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Equal(t, "Bearer token123", result.Get(header.Authorization),
			"subgraph subscriptions bypass transport so auth must be propagated here")
	})

	t.Run("should propagate custom auth header name from AuthConfigs", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set("X-Custom-Auth", "my-secret-key")

		apiDef := &apidef.APIDefinition{
			StripAuthData:   false,
			UseStandardAuth: true,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		apiDef.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {AuthHeaderName: "X-Custom-Auth"},
		}

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Equal(t, "my-secret-key", result.Get("X-Custom-Auth"))
	})

	t.Run("should propagate auth header from deprecated Auth field when AuthConfigs is empty", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set("X-Legacy-Auth", "legacy-key")

		apiDef := &apidef.APIDefinition{
			StripAuthData: false,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeSupergraph
		apiDef.Auth = apidef.AuthConfig{AuthHeaderName: "X-Legacy-Auth"}

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Equal(t, "legacy-key", result.Get("X-Legacy-Auth"))
	})

	t.Run("should not propagate auth header when DisableHeader is true", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set(header.Authorization, "Bearer token123")

		apiDef := &apidef.APIDefinition{
			StripAuthData:   false,
			UseStandardAuth: true,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		apiDef.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {DisableHeader: true},
		}

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Empty(t, result.Get(header.Authorization))
	})

	t.Run("should not overwrite existing global headers with auth header", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set(header.Authorization, "Bearer from-client")

		apiDef := &apidef.APIDefinition{
			StripAuthData:   false,
			UseStandardAuth: true,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		apiDef.GraphQL.Engine.GlobalHeaders = []apidef.UDGGlobalHeader{
			{Key: header.Authorization, Value: "Bearer from-global-config"},
		}

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		// Auth propagation runs after global headers, so the client auth header
		// should take precedence when StripAuthData is false.
		assert.Equal(t, "Bearer from-client", result.Get(header.Authorization))
	})

	t.Run("should not propagate when auth header is absent from request", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		// No Authorization header set

		apiDef := &apidef.APIDefinition{
			StripAuthData:   false,
			UseStandardAuth: true,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Empty(t, result.Get(header.Authorization))
	})

	t.Run("should not propagate when active auth type has no AuthConfigs entry and no fallback", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set(header.Authorization, "Bearer token123")

		apiDef := &apidef.APIDefinition{
			StripAuthData: false,
			UseBasicAuth:  true,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		// AuthConfigs is empty — no "basic" key present, and BasicType doesn't
		// qualify for the deprecated Auth field fallback.

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Empty(t, result.Get(header.Authorization),
			"should return early when active auth config is missing and not eligible for fallback")
	})

	t.Run("should propagate JWT auth header when EnableJWT is true", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set(header.Authorization, "Bearer jwt-token")

		apiDef := &apidef.APIDefinition{
			StripAuthData: false,
			EnableJWT:     true,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		apiDef.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.JWTType: {AuthHeaderName: ""},
		}

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Equal(t, "Bearer jwt-token", result.Get(header.Authorization))
	})

	t.Run("should not propagate auth header for keyless API", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set(header.Authorization, "Bearer token123")

		apiDef := &apidef.APIDefinition{
			StripAuthData:    false,
			UseKeylessAccess: true,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Empty(t, result.Get(header.Authorization),
			"keyless APIs should not propagate any auth headers")
	})

	t.Run("should only propagate active auth method header not inactive ones", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)
		req.Header.Set(header.Authorization, "Bearer jwt-token")
		req.Header.Set("X-Basic-Auth", "basic-creds")

		apiDef := &apidef.APIDefinition{
			StripAuthData: false,
			EnableJWT:     true,
		}
		apiDef.GraphQL.Enabled = true
		apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		apiDef.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.JWTType:   {},
			apidef.BasicType: {AuthHeaderName: "X-Basic-Auth"},
		}

		result := additionalUpstreamHeaders(testLogger(), req, apiDef)
		assert.Equal(t, "Bearer jwt-token", result.Get(header.Authorization),
			"active JWT auth header should be propagated")
		assert.Empty(t, result.Get("X-Basic-Auth"),
			"inactive basic auth header should not be propagated")
	})
}

func TestActiveAuthType(t *testing.T) {
	tests := []struct {
		name     string
		apiDef   *apidef.APIDefinition
		expected string
	}{
		{
			name:     "returns empty string for keyless access",
			apiDef:   &apidef.APIDefinition{UseKeylessAccess: true},
			expected: "",
		},
		{
			name:     "returns JWTType when EnableJWT is true",
			apiDef:   &apidef.APIDefinition{EnableJWT: true},
			expected: apidef.JWTType,
		},
		{
			name:     "returns BasicType when UseBasicAuth is true",
			apiDef:   &apidef.APIDefinition{UseBasicAuth: true},
			expected: apidef.BasicType,
		},
		{
			name:     "returns HMACType when EnableSignatureChecking is true",
			apiDef:   &apidef.APIDefinition{EnableSignatureChecking: true},
			expected: apidef.HMACType,
		},
		{
			name:     "returns OAuthType when UseOauth2 is true",
			apiDef:   &apidef.APIDefinition{UseOauth2: true},
			expected: apidef.OAuthType,
		},
		{
			name: "returns ExternalOAuthType when ExternalOAuth is enabled",
			apiDef: func() *apidef.APIDefinition {
				def := &apidef.APIDefinition{}
				def.ExternalOAuth.Enabled = true
				return def
			}(),
			expected: apidef.ExternalOAuthType,
		},
		{
			name:     "returns OIDCType when UseOpenID is true",
			apiDef:   &apidef.APIDefinition{UseOpenID: true},
			expected: apidef.OIDCType,
		},
		{
			name:     "returns AuthTokenType when UseStandardAuth is true",
			apiDef:   &apidef.APIDefinition{UseStandardAuth: true},
			expected: apidef.AuthTokenType,
		},
		{
			name:     "returns AuthTokenType as default fallback",
			apiDef:   &apidef.APIDefinition{},
			expected: apidef.AuthTokenType,
		},
		{
			name:     "keyless takes precedence over other flags",
			apiDef:   &apidef.APIDefinition{UseKeylessAccess: true, EnableJWT: true},
			expected: "",
		},
		{
			name:     "JWT takes precedence over basic auth",
			apiDef:   &apidef.APIDefinition{EnableJWT: true, UseBasicAuth: true},
			expected: apidef.JWTType,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := activeAuthType(tc.apiDef)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestAdditionalUpstreamHeaders_NoAuthHeaderLeakAcrossConnections simulates two
// separate WebSocket subscription connections (each with a different auth token)
// and verifies that:
//  1. Each call to additionalUpstreamHeaders returns headers scoped to its own request.
//  2. Mutating one connection's upstream headers does not affect another's.
//  3. A subsequent connection never sees a previous connection's auth token.
func TestAdditionalUpstreamHeaders_NoAuthHeaderLeakAcrossConnections(t *testing.T) {
	logger := testLogger()

	apiDef := &apidef.APIDefinition{
		StripAuthData:   false,
		UseStandardAuth: true,
	}
	apiDef.GraphQL.Enabled = true
	apiDef.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine

	// Simulate first WebSocket connection with User A's token
	reqConnA, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/graphql", nil)
	require.NoError(t, err)
	reqConnA.Header.Set(header.Authorization, "Bearer user-a-token")

	headersConnA := additionalUpstreamHeaders(logger, reqConnA, apiDef)

	// Simulate second WebSocket connection with User B's token
	reqConnB, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/graphql", nil)
	require.NoError(t, err)
	reqConnB.Header.Set(header.Authorization, "Bearer user-b-token")

	headersConnB := additionalUpstreamHeaders(logger, reqConnB, apiDef)

	t.Run("each connection should have its own auth token", func(t *testing.T) {
		assert.Equal(t, "Bearer user-a-token", headersConnA.Get(header.Authorization))
		assert.Equal(t, "Bearer user-b-token", headersConnB.Get(header.Authorization))
	})

	t.Run("mutating one connection's headers should not affect the other", func(t *testing.T) {
		headersConnA.Set(header.Authorization, "Bearer mutated-token")

		assert.Equal(t, "Bearer mutated-token", headersConnA.Get(header.Authorization),
			"connection A's headers should reflect its own mutation")
		assert.Equal(t, "Bearer user-b-token", headersConnB.Get(header.Authorization),
			"connection B's headers must not be affected by mutation of connection A")
	})

	t.Run("new connection after previous connection should not inherit old auth", func(t *testing.T) {
		// Simulate connection A being torn down and a new connection C arriving
		reqConnC, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/graphql", nil)
		require.NoError(t, err)
		reqConnC.Header.Set(header.Authorization, "Bearer user-c-token")

		headersConnC := additionalUpstreamHeaders(logger, reqConnC, apiDef)

		assert.Equal(t, "Bearer user-c-token", headersConnC.Get(header.Authorization),
			"connection C should only see its own token")
		assert.NotEqual(t, headersConnA.Get(header.Authorization), headersConnC.Get(header.Authorization),
			"connection C must not inherit connection A's mutated token")
	})

	t.Run("connection without auth header should not see previous connection's token", func(t *testing.T) {
		reqNoAuth, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/graphql", nil)
		require.NoError(t, err)
		// No Authorization header set

		headersNoAuth := additionalUpstreamHeaders(logger, reqNoAuth, apiDef)

		assert.Empty(t, headersNoAuth.Get(header.Authorization),
			"unauthenticated connection must not inherit any previous connection's auth token")
	})
}
