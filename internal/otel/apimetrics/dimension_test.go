package apimetrics

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/user"
)

func makeRequestContext() *RequestContext {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	return &RequestContext{
		Request:             r,
		StatusCode:          200,
		APIID:               "api-123",
		APIName:             "TestAPI",
		OrgID:               "org-456",
		ListenPath:          "/test",
		Token:               "abcdefghijklmnop",
		APIVersion:          "v1",
		ErrorClassification: "",
		LatencyTotal:        150,
		LatencyUpstream:     100,
		LatencyGateway:      50,
	}
}

func TestCompileExtractor_MetadataMethod(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "method", Label: "http.method"})
	require.NoError(t, err)
	assert.Equal(t, "http.method", ext.Label)

	rc := makeRequestContext()
	assert.Equal(t, "GET", ext.Extract(rc))
}

func TestCompileExtractor_MetadataResponseCode(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "response_code"})
	require.NoError(t, err)

	rc := makeRequestContext()
	rc.StatusCode = 404
	assert.Equal(t, "404", ext.Extract(rc))
}

func TestCompileExtractor_MetadataListenPath(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "listen_path"})
	require.NoError(t, err)

	rc := makeRequestContext()
	assert.Equal(t, "/test", ext.Extract(rc))
}

func TestCompileExtractor_MetadataEndpoint(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "endpoint"})
	require.NoError(t, err)

	rc := makeRequestContext()
	rc.Endpoint = "/users/123"
	assert.Equal(t, "/users/123", ext.Extract(rc))

	rc.Endpoint = ""
	assert.Equal(t, "", ext.Extract(rc))
}

func TestCompileExtractor_MetadataAPIID(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "api_id"})
	require.NoError(t, err)

	rc := makeRequestContext()
	assert.Equal(t, "api-123", ext.Extract(rc))
}

func TestCompileExtractor_MetadataAPIName(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "api_name"})
	require.NoError(t, err)

	rc := makeRequestContext()
	assert.Equal(t, "TestAPI", ext.Extract(rc))
}

func TestCompileExtractor_MetadataOrgID(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "org_id"})
	require.NoError(t, err)

	rc := makeRequestContext()
	assert.Equal(t, "org-456", ext.Extract(rc))
}

func TestCompileExtractor_MetadataResponseFlag(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "response_flag"})
	require.NoError(t, err)

	t.Run("with error classification", func(t *testing.T) {
		rc := makeRequestContext()
		rc.ErrorClassification = "RateLimitExceeded"
		assert.Equal(t, "RateLimitExceeded", ext.Extract(rc))
	})

	t.Run("without error classification falls back to status code", func(t *testing.T) {
		rc := makeRequestContext()
		rc.ErrorClassification = ""
		rc.StatusCode = 200
		assert.Equal(t, "200", ext.Extract(rc))
	})
}

func TestCompileExtractor_MetadataIPAddress(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "ip_address"})
	require.NoError(t, err)

	// ip_address reads from rc.IPAddress (pre-resolved by the recording site via request.RealIP).
	rc := makeRequestContext()
	rc.IPAddress = "10.0.0.1"

	val := ext.Extract(rc)
	assert.Equal(t, "10.0.0.1", val, "ip_address extractor should return the pre-resolved IP")

	// Empty IPAddress should return empty string.
	rc.IPAddress = ""
	assert.Empty(t, ext.Extract(rc), "ip_address extractor should return empty when IPAddress is not set")
}

func TestCompileExtractor_MetadataAPIVersion(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "api_version"})
	require.NoError(t, err)

	rc := makeRequestContext()
	assert.Equal(t, "v1", ext.Extract(rc))
}

func TestCompileExtractor_MetadataHost(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "host"})
	require.NoError(t, err)

	rc := makeRequestContext()
	assert.Equal(t, "example.com", ext.Extract(rc))
}

func TestCompileExtractor_MetadataScheme(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "scheme"})
	require.NoError(t, err)

	t.Run("http when no TLS", func(t *testing.T) {
		rc := makeRequestContext()
		assert.Equal(t, "http", ext.Extract(rc))
	})

	t.Run("https when TLS present", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Request.TLS = &tls.ConnectionState{}
		assert.Equal(t, "https", ext.Extract(rc))
	})
}

func TestCompileExtractor_SessionAPIKey(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "session", Key: "api_key"})
	require.NoError(t, err)

	t.Run("returns truncated token", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Token = "abcdefghijklmnop"
		val := ext.Extract(rc)
		assert.Equal(t, "klmnop", val) // last 6 chars of the token
	})

	t.Run("returns empty when no token", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Token = ""
		assert.Equal(t, "", ext.Extract(rc))
	})
}

func TestCompileExtractor_SessionOAuthID(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "session", Key: "oauth_id"})
	require.NoError(t, err)

	t.Run("returns oauth client ID", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = &user.SessionState{OauthClientID: "client-xyz"}
		assert.Equal(t, "client-xyz", ext.Extract(rc))
	})

	t.Run("returns empty when session nil", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = nil
		assert.Equal(t, "", ext.Extract(rc))
	})
}

func TestCompileExtractor_SessionAlias(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "session", Key: "alias"})
	require.NoError(t, err)

	t.Run("returns alias", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = &user.SessionState{Alias: "user-alias"}
		assert.Equal(t, "user-alias", ext.Extract(rc))
	})

	t.Run("returns empty when session nil", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = nil
		assert.Equal(t, "", ext.Extract(rc))
	})
}

func TestCompileExtractor_SessionPortalApp(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "session", Key: "portal_app"})
	require.NoError(t, err)

	t.Run("returns app ID from portal tag", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = &user.SessionState{Tags: []string{"portal-app-123"}}
		assert.Equal(t, "123", ext.Extract(rc))
	})

	t.Run("returns first match when multiple tags", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = &user.SessionState{Tags: []string{"other-tag", "portal-app-456", "portal-org-789"}}
		assert.Equal(t, "456", ext.Extract(rc))
	})

	t.Run("returns empty when no portal-app tag", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = &user.SessionState{Tags: []string{"portal-org-789"}}
		assert.Equal(t, "", ext.Extract(rc))
	})

	t.Run("returns empty when session nil", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = nil
		assert.Equal(t, "", ext.Extract(rc))
	})
}

func TestCompileExtractor_SessionPortalOrg(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "session", Key: "portal_org"})
	require.NoError(t, err)

	t.Run("returns org ID from portal tag", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = &user.SessionState{Tags: []string{"portal-org-789"}}
		assert.Equal(t, "789", ext.Extract(rc))
	})

	t.Run("returns first match when multiple tags", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = &user.SessionState{Tags: []string{"portal-app-123", "portal-org-456"}}
		assert.Equal(t, "456", ext.Extract(rc))
	})

	t.Run("returns empty when no portal-org tag", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = &user.SessionState{Tags: []string{"portal-app-123"}}
		assert.Equal(t, "", ext.Extract(rc))
	})

	t.Run("returns empty when session nil", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Session = nil
		assert.Equal(t, "", ext.Extract(rc))
	})
}

func TestCompileExtractor_Header(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "header", Key: "X-Customer-ID", Label: "customer_id"})
	require.NoError(t, err)
	assert.Equal(t, "customer_id", ext.Label)

	t.Run("reads from request header", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Request.Header.Set("X-Customer-ID", "cust-42")
		assert.Equal(t, "cust-42", ext.Extract(rc))
	})

	t.Run("returns empty when header missing", func(t *testing.T) {
		rc := makeRequestContext()
		assert.Equal(t, "", ext.Extract(rc))
	})

	t.Run("returns empty when request nil", func(t *testing.T) {
		rc := &RequestContext{}
		assert.Equal(t, "", ext.Extract(rc))
	})
}

func TestCompileExtractor_Context(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "context", Key: "tier", Label: "tier"})
	require.NoError(t, err)

	t.Run("reads from context variables map", func(t *testing.T) {
		rc := makeRequestContext()
		rc.ContextVariables = map[string]interface{}{"tier": "premium"}
		assert.Equal(t, "premium", ext.Extract(rc))
	})

	t.Run("returns empty when key missing", func(t *testing.T) {
		rc := makeRequestContext()
		rc.ContextVariables = map[string]interface{}{"other": "value"}
		assert.Equal(t, "", ext.Extract(rc))
	})

	t.Run("returns empty when context variables nil", func(t *testing.T) {
		rc := makeRequestContext()
		rc.ContextVariables = nil
		assert.Equal(t, "", ext.Extract(rc))
	})

	t.Run("converts non-string values via Sprint", func(t *testing.T) {
		rc := makeRequestContext()
		rc.ContextVariables = map[string]interface{}{"tier": 42}
		assert.Equal(t, "42", ext.Extract(rc))
	})
}

func TestCompileExtractor_ResponseHeader(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "response_header", Key: "X-Cache-Status", Label: "cache_status"})
	require.NoError(t, err)

	t.Run("reads from response header", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Response = &http.Response{
			Header: http.Header{"X-Cache-Status": []string{"HIT"}},
		}
		assert.Equal(t, "HIT", ext.Extract(rc))
	})

	t.Run("returns empty when response nil", func(t *testing.T) {
		rc := makeRequestContext()
		rc.Response = nil
		assert.Equal(t, "", ext.Extract(rc))
	})
}

func TestCompileExtractor_DefaultLabel(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "header", Key: "X-Custom"})
	require.NoError(t, err)
	assert.Equal(t, "X-Custom", ext.Label, "label should default to key when omitted")
}

func TestCompileExtractor_UnknownSource(t *testing.T) {
	_, err := CompileExtractor(DimensionDefinition{Source: "unknown_source", Key: "anything"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown dimension source")
}

func TestCompileExtractor_UnknownMetadataKey(t *testing.T) {
	_, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "nonexistent"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown metadata key")
}

func TestCompileExtractor_UnknownSessionKey(t *testing.T) {
	_, err := CompileExtractor(DimensionDefinition{Source: "session", Key: "nonexistent"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown session key")
}

func TestCompileExtractor_MetadataMethodNilRequest(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "method"})
	require.NoError(t, err)

	rc := &RequestContext{}
	assert.Equal(t, "", ext.Extract(rc))
}

func TestCompileExtractor_MetadataHostNilRequest(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "host"})
	require.NoError(t, err)

	rc := &RequestContext{}
	assert.Equal(t, "", ext.Extract(rc))
}

func TestCompileExtractor_MetadataSchemeNilRequest(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "scheme"})
	require.NoError(t, err)

	rc := &RequestContext{}
	assert.Equal(t, "http", ext.Extract(rc), "nil request should return http")
}

func TestCompileExtractor_MetadataMCPMethod(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "mcp_method"})
	require.NoError(t, err)

	rc := makeRequestContext()
	rc.MCPMethod = "tools/call"
	assert.Equal(t, "tools/call", ext.Extract(rc))
}

func TestCompileExtractor_MetadataMCPPrimitiveType(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "mcp_primitive_type"})
	require.NoError(t, err)

	rc := makeRequestContext()
	rc.MCPPrimitiveType = "tool"
	assert.Equal(t, "tool", ext.Extract(rc))
}

func TestCompileExtractor_MetadataMCPPrimitiveName(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "mcp_primitive_name"})
	require.NoError(t, err)

	rc := makeRequestContext()
	rc.MCPPrimitiveName = "get_weather"
	assert.Equal(t, "get_weather", ext.Extract(rc))
}

func TestCompileExtractor_MetadataMCPErrorCode(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "mcp_error_code"})
	require.NoError(t, err)

	t.Run("returns string representation for non-zero code", func(t *testing.T) {
		rc := makeRequestContext()
		rc.MCPErrorCode = -32601
		assert.Equal(t, "-32601", ext.Extract(rc))
	})

	t.Run("returns empty string for zero code", func(t *testing.T) {
		rc := makeRequestContext()
		rc.MCPErrorCode = 0
		assert.Equal(t, "", ext.Extract(rc))
	})
}

func TestCompileExtractor_MCPExtractorsEmptyWhenNotSet(t *testing.T) {
	mcpKeys := []string{"mcp_method", "mcp_primitive_type", "mcp_primitive_name", "mcp_error_code"}

	for _, key := range mcpKeys {
		t.Run(key, func(t *testing.T) {
			ext, err := CompileExtractor(DimensionDefinition{Source: "metadata", Key: key})
			require.NoError(t, err)

			// Zero-valued RequestContext (non-MCP API case).
			rc := makeRequestContext()
			assert.Equal(t, "", ext.Extract(rc), "MCP extractor %q should return empty for non-MCP request", key)
		})
	}
}

func TestCompileExtractor_ConfigData(t *testing.T) {
	ext, err := CompileExtractor(DimensionDefinition{Source: "config_data", Key: "environment", Label: "config_data.environment"})
	require.NoError(t, err)
	assert.Equal(t, "config_data.environment", ext.Label)

	t.Run("reads from config data map", func(t *testing.T) {
		rc := makeRequestContext()
		rc.ConfigData = map[string]interface{}{"environment": "production"}
		assert.Equal(t, "production", ext.Extract(rc))
	})

	t.Run("returns empty when key missing", func(t *testing.T) {
		rc := makeRequestContext()
		rc.ConfigData = map[string]interface{}{"other": "value"}
		assert.Equal(t, "", ext.Extract(rc))
	})

	t.Run("returns empty when config data nil", func(t *testing.T) {
		rc := makeRequestContext()
		rc.ConfigData = nil
		assert.Equal(t, "", ext.Extract(rc))
	})

	t.Run("converts non-string values via Sprint", func(t *testing.T) {
		rc := makeRequestContext()
		rc.ConfigData = map[string]interface{}{"environment": 42}
		assert.Equal(t, "42", ext.Extract(rc))
	})
}

func BenchmarkCompileExtractor_Metadata(b *testing.B) {
	dim := DimensionDefinition{Source: "metadata", Key: "method", Label: "http.method"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompileExtractor(dim)
	}
}

func BenchmarkDimensionExtractor_Extract(b *testing.B) {
	ext, _ := CompileExtractor(DimensionDefinition{Source: "metadata", Key: "method"})
	rc := makeRequestContext()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext.Extract(rc)
	}
}

func BenchmarkDimensionExtractor_HeaderExtract(b *testing.B) {
	ext, _ := CompileExtractor(DimensionDefinition{Source: "header", Key: "X-Customer-ID"})
	rc := makeRequestContext()
	rc.Request.Header.Set("X-Customer-ID", "cust-42")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext.Extract(rc)
	}
}

func BenchmarkDimensionExtractor_SessionExtract(b *testing.B) {
	ext, _ := CompileExtractor(DimensionDefinition{Source: "session", Key: "api_key"})
	rc := makeRequestContext()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext.Extract(rc)
	}
}

func TestTruncateKey(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"long token", "abcdefghijklmnop", "klmnop"},
		{"exactly 6 chars", "abcdef", "abcdef"},
		{"short token", "abc", "abc"},
		{"empty token", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, truncateKey(tt.input))
		})
	}
}
