package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	ctxpkg "github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/user"
)

func TestObfuscateAuthorizationHeaders(t *testing.T) {
	tests := []struct {
		name           string
		spec           *APISpec
		headers        map[string]string
		expectedHeader map[string]string
	}{
		{
			name: "Default Authorization header",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Auth: apidef.AuthConfig{}, // Empty AuthHeaderName defaults to "Authorization"
				},
			},
			headers: map[string]string{
				"Authorization": "Bearer secret-token",
				"X-Custom":      "value",
			},
			expectedHeader: map[string]string{
				"Authorization": obfuscationToken,
				"X-Custom":      "value",
			},
		},
		{
			name: "Custom AuthHeaderName in spec.Auth",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Auth: apidef.AuthConfig{
						AuthHeaderName: "X-Api-Key",
					},
				},
			},
			headers: map[string]string{
				"X-Api-Key": "my-secret-key",
			},
			expectedHeader: map[string]string{
				"X-Api-Key": obfuscationToken,
			},
		},
		{
			name: "Multiple AuthConfigs",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					AuthConfigs: map[string]apidef.AuthConfig{
						"jwt":  {AuthHeaderName: "X-Jwt-Token"},
						"oidc": {AuthHeaderName: "X-Oidc-Token"},
					},
				},
			},
			headers: map[string]string{
				"X-Jwt-Token":  "jwt-secret",
				"X-Oidc-Token": "oidc-secret",
				"X-Normal":     "normal-value",
			},
			expectedHeader: map[string]string{
				"X-Jwt-Token":  obfuscationToken,
				"X-Oidc-Token": obfuscationToken,
				"X-Normal":     "normal-value",
			},
		},
		{
			name: "DisableHeader is true",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Auth: apidef.AuthConfig{
						AuthHeaderName: "Authorization",
						DisableHeader:  true,
					},
				},
			},
			headers: map[string]string{
				"Authorization": "Bearer secret-token",
			},
			expectedHeader: map[string]string{
				"Authorization": "Bearer secret-token",
			},
		},
		{
			name: "Case insensitivity",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Auth: apidef.AuthConfig{
						AuthHeaderName: "x-api-key",
					},
				},
			},
			headers: map[string]string{
				"X-API-KEY": "secret-key",
			},
			expectedHeader: map[string]string{
				"X-Api-Key": obfuscationToken,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			require.NoError(t, err)

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			expectedOriginalHeaders := req.Header.Clone()
			returnedOriginalHeaders := obfuscateAuthorizationHeaders(req, tt.spec)

			for k, v := range tt.expectedHeader {
				assert.Equal(t, v, req.Header.Get(k), "Mutated header %s mismatch", k)
			}

			assert.Equal(t, expectedOriginalHeaders, returnedOriginalHeaders, "Returned original headers mismatch")
		})
	}
}

func TestGetRawRequest(t *testing.T) {
	tests := []struct {
		name                    string
		allowUnsafeDetailedLogs bool
		headers                 map[string]string
		expectObfuscated        bool
	}{
		{
			name:                    "Secure by default (AllowUnsafeDetailedLogs = false)",
			allowUnsafeDetailedLogs: false,
			headers: map[string]string{
				"Authorization": "Bearer secret-token",
				"X-Custom":      "value",
			},
			expectObfuscated: true,
		},
		{
			name:                    "Legacy unsafe mode (AllowUnsafeDetailedLogs = true)",
			allowUnsafeDetailedLogs: true,
			headers: map[string]string{
				"Authorization": "Bearer secret-token",
				"X-Custom":      "value",
			},
			expectObfuscated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := "body-content"
			req, err := http.NewRequest("GET", "/test-path", bytes.NewBufferString(content))
			require.NoError(t, err)
			req.Host = "localhost"

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			expectedRestoredHeaders := req.Header.Clone()

			spec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Auth: apidef.AuthConfig{}, // Defaults to Authorization
				},
			}

			spec.GlobalConfig = config.Config{
				AnalyticsConfig: config.AnalyticsConfigConfig{
					AllowUnsafeDetailedLogs: tt.allowUnsafeDetailedLogs,
				},
			}

			rawRequestBase64 := getRawRequest(req, spec)
			rawRequestBytes, err := base64.StdEncoding.DecodeString(rawRequestBase64)
			require.NoError(t, err)
			rawRequestStr := string(rawRequestBytes)

			assert.Contains(t, rawRequestStr, "GET /test-path HTTP/1.1")
			assert.Contains(t, rawRequestStr, content)
			assert.Contains(t, rawRequestStr, "X-Custom: value")

			if tt.expectObfuscated {
				assert.Contains(t, rawRequestStr, "Authorization: "+obfuscationToken)
				assert.NotContains(t, rawRequestStr, "Bearer secret-token")
			} else {
				assert.Contains(t, rawRequestStr, "Authorization: Bearer secret-token")
				assert.NotContains(t, rawRequestStr, "Authorization: "+obfuscationToken)
			}

			assert.Equal(t, expectedRestoredHeaders, req.Header, "Original request headers were not restored")
		})
	}
}

func TestRecordDetail(t *testing.T) {
	testcases := []struct {
		title   string
		spec    *APISpec
		binding bindContextFunc
		expect  bool
	}{
		{
			title:  "empty session",
			spec:   testAPISpec(nil),
			expect: false,
		},
		{
			title: "empty session, enabled analytics",
			spec: testAPISpec(func(spec *APISpec) {
				spec.EnableDetailedRecording = true
			}),
			expect: true,
		},
		{
			title: "empty session, enabled config",
			spec: testAPISpec(func(spec *APISpec) {
				spec.GlobalConfig.EnforceOrgDataDetailLogging = false
				spec.GlobalConfig.AnalyticsConfig.EnableDetailedRecording = true
			}),
			expect: true,
		},
		{
			title: "normal session",
			spec:  testAPISpec(nil),
			// attach user session
			binding: func(ctx context.Context) context.Context {
				session := &user.SessionState{
					EnableDetailedRecording: true,
				}
				return context.WithValue(ctx, ctxpkg.SessionData, session)
			},
			expect: true,
		},
		{
			title: "org empty session",
			spec: testAPISpec(func(spec *APISpec) {
				spec.GlobalConfig.EnforceOrgDataDetailLogging = true
			}),
			expect: false,
		},
		{
			title: "org session",
			spec: testAPISpec(func(spec *APISpec) {
				spec.GlobalConfig.EnforceOrgDataDetailLogging = true
			}),
			// attach user session
			binding: func(ctx context.Context) context.Context {
				session := &user.SessionState{
					EnableDetailedRecording: true,
				}
				return context.WithValue(ctx, ctxpkg.OrgSessionContext, session)
			},
			expect: true,
		},
		{
			title: "graphql request",
			spec: testAPISpec(func(spec *APISpec) {
				spec.GraphQL.Enabled = true
			}),
			expect: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.title, func(t *testing.T) {
			req := testRequestWithContext(tc.binding)
			got := recordDetail(req, tc.spec)
			assert.Equal(t, tc.expect, got)
		})
	}
}
