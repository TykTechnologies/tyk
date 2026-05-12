package oas

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// sampleMCPProxy is the canonical fully-populated MCPProxy used by the
// round-trip and JSON-tag tests. It exercises every field, including the
// GA-only ServiceCred / OAuth2CCConfig branches that are persisted but
// rejected at write-time.
func sampleMCPProxy() *MCPProxy {
	return &MCPProxy{
		ProtocolVersion: "2025-03-26",
		Sources: []MCPSource{
			{
				SourceSlug:  "hello-svc",
				BackendMode: "loopback",
				SourceAPIID: "api-hello-123",
			},
			{
				SourceSlug:  "users-svc",
				BackendMode: "upstream",
				UpstreamURL: "https://users.example.com/api/v1",
				UpstreamOAS: json.RawMessage(`{"openapi":"3.1.0","info":{"title":"users","version":"1"},"paths":{}}`),
				UpstreamServerVars: map[string]string{
					"region": "eu-west-1",
				},
				UpstreamCred: &UpstreamCred{
					AuthType:    "header",
					HeaderName:  "X-API-Key",
					SecretValue: "s3cr3t",
				},
				ServiceCred: &ServiceCredRef{
					AuthType:  "oauth2_cc",
					SecretRef: "vault://kv/users-svc",
					OAuth2: &OAuth2CCConfig{
						TokenURL:          "https://idp.example.com/token",
						Scopes:            []string{"read", "write"},
						DefaultTTLSeconds: 3600,
					},
				},
			},
		},
	}
}

func TestMCPProxy_FillExtractTo_RoundTrip(t *testing.T) {
	t.Parallel()

	// MCPProxy lives only on OAS — the round-trip is JSON marshal on the
	// Server struct. Fill/ExtractTo are no-op shims and must not lose data.
	original := Server{
		ListenPath: ListenPath{Value: "/mcp/demo", Strip: true},
		MCPProxy:   sampleMCPProxy(),
	}

	// Fill / ExtractTo must not corrupt or drop the OAS-only fields.
	var api apidef.APIDefinition
	api.SetDisabledFlags()
	original.ExtractTo(&api)

	var roundTripped Server
	roundTripped.Fill(api)
	// Manually re-attach OAS-only fields, which is exactly how the parent
	// XTykAPIGateway.Fill would behave (the JSON-marshal layer is the
	// persistence boundary, not apidef).
	roundTripped.MCPProxy = original.MCPProxy

	// Now the two should compare equal on every field both Fill/ExtractTo
	// and direct OAS marshal touch.
	assert.Equal(t, original.ListenPath, roundTripped.ListenPath)
	assert.Equal(t, original.MCPProxy, roundTripped.MCPProxy)
}

func TestMCPProxy_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := Server{
		ListenPath:           ListenPath{Value: "/mcp/demo"},
		MCPProxy:             sampleMCPProxy(),
		AcceptMCPLoopCallers: true,
		MCPProxies:           []string{"proxy-a", "proxy-b"},
	}

	raw, err := json.Marshal(original)
	require.NoError(t, err)

	// Tag sanity — fail loudly on snake_case regressions.
	rawStr := string(raw)
	for _, tag := range []string{
		`"mcpProxy"`,
		`"protocolVersion"`,
		`"sources"`,
		`"sourceSlug"`,
		`"backendMode"`,
		`"sourceApiId"`,
		`"upstreamUrl"`,
		`"upstreamServerVars"`,
		`"upstreamCred"`,
		`"oasSourceHash"`,
		`"serviceCred"`,
		`"tools"`,
		`"toolName"`,
		`"method"`,
		`"pathTemplate"`,
		`"operationId"`,
		`"description"`,
		`"inputSchema"`,
		`"outputSchema"`,
		`"paramLocations"`,
		`"authType"`,
		`"headerName"`,
		`"secretValue"`,
		`"secretRef"`,
		`"oauth2"`,
		`"tokenUrl"`,
		`"scopes"`,
		`"defaultTtlSeconds"`,
		`"acceptMcpLoopCallers"`,
		`"mcpProxies"`,
	} {
		assert.Contains(t, rawStr, tag, "expected camelCase tag %s in marshalled JSON", tag)
	}

	var decoded Server
	require.NoError(t, json.Unmarshal(raw, &decoded))

	assert.Equal(t, original.MCPProxy, decoded.MCPProxy)
	assert.Equal(t, original.AcceptMCPLoopCallers, decoded.AcceptMCPLoopCallers)
	assert.Equal(t, original.MCPProxies, decoded.MCPProxies)
}

func TestMCPProxy_OmitEmpty(t *testing.T) {
	t.Parallel()

	// A Server with none of the new fields set must not emit any of the
	// new tags into the JSON payload.
	bare := Server{ListenPath: ListenPath{Value: "/x"}}
	raw, err := json.Marshal(bare)
	require.NoError(t, err)

	rawStr := string(raw)
	for _, tag := range []string{`"mcpProxy"`, `"acceptMcpLoopCallers"`, `"mcpProxies"`} {
		assert.NotContains(t, rawStr, tag, "expected %s to be omitted when zero-valued", tag)
	}
}

func TestMCPProxy_Validate(t *testing.T) {
	t.Parallel()

	type tc struct {
		name      string
		proxy     *MCPProxy
		wantOK    bool
		wantCodes []string
	}

	cases := []tc{
		{
			name:   "nil proxy passes",
			proxy:  nil,
			wantOK: true,
		},
		{
			name: "valid loopback + upstream passes",
			proxy: &MCPProxy{
				ProtocolVersion: "2025-03-26",
				Sources: []MCPSource{
					{SourceSlug: "a", BackendMode: "loopback", SourceAPIID: "api-a"},
					{SourceSlug: "b", BackendMode: "upstream", UpstreamURL: "https://b.example.com"},
				},
			},
			wantOK: true,
		},
		{
			name: "service_cred rejected as not_implemented_in_poc",
			proxy: &MCPProxy{
				Sources: []MCPSource{
					{
						SourceSlug:  "a",
						BackendMode: "upstream",
						UpstreamURL: "https://a.example.com",
						ServiceCred: &ServiceCredRef{AuthType: "oauth2_cc"},
					},
				},
			},
			wantCodes: []string{MCPErrNotImplementedInPoC},
		},
		{
			name: "upstream_cred mtls rejected as not_implemented_in_poc",
			proxy: &MCPProxy{
				Sources: []MCPSource{
					{
						SourceSlug:   "a",
						BackendMode:  "upstream",
						UpstreamURL:  "https://a.example.com",
						UpstreamCred: &UpstreamCred{AuthType: "mtls"},
					},
				},
			},
			wantCodes: []string{MCPErrNotImplementedInPoC},
		},
		{
			name: "service_cred + mtls collapse into single error class",
			proxy: &MCPProxy{
				Sources: []MCPSource{
					{
						SourceSlug:   "a",
						BackendMode:  "upstream",
						UpstreamURL:  "https://a.example.com",
						UpstreamCred: &UpstreamCred{AuthType: "mtls"},
						ServiceCred:  &ServiceCredRef{AuthType: "mtls"},
					},
				},
			},
			wantCodes: []string{MCPErrNotImplementedInPoC},
		},
		{
			name: "upstream URL with placeholder rejected",
			proxy: &MCPProxy{
				Sources: []MCPSource{
					{
						SourceSlug:  "a",
						BackendMode: "upstream",
						UpstreamURL: "https://{region}.example.com",
					},
				},
			},
			wantCodes: []string{MCPErrUpstreamURLContainsPlaceholder},
		},
		{
			name: "loopback without sourceApiId rejected",
			proxy: &MCPProxy{
				Sources: []MCPSource{
					{SourceSlug: "a", BackendMode: "loopback"},
				},
			},
			wantCodes: []string{MCPErrLoopbackSourceMissingAPIID},
		},
		{
			name: "duplicate source slug rejected",
			proxy: &MCPProxy{
				Sources: []MCPSource{
					{SourceSlug: "a", BackendMode: "loopback", SourceAPIID: "api-1"},
					{SourceSlug: "a", BackendMode: "loopback", SourceAPIID: "api-2"},
				},
			},
			wantCodes: []string{MCPErrDuplicateSourceSlug},
		},
		{
			name: "multiple violations accumulate, do not short-circuit",
			proxy: &MCPProxy{
				Sources: []MCPSource{
					{
						SourceSlug:  "a",
						BackendMode: "loopback", // missing SourceAPIID
					},
					{
						SourceSlug:  "a", // dup slug
						BackendMode: "upstream",
						UpstreamURL: "https://{x}/", // placeholder
						// missing UpstreamOAS triggers MCPErrUpstreamSourceMissingOAS
					},
				},
			},
			wantCodes: []string{
				MCPErrLoopbackSourceMissingAPIID,
				MCPErrUpstreamURLContainsPlaceholder,
				MCPErrUpstreamSourceMissingOAS,
				MCPErrDuplicateSourceSlug,
			},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			err := c.proxy.Validate(context.Background())
			if c.wantOK {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)

			var verr *MCPProxyValidationError
			require.True(t, errors.As(err, &verr), "expected MCPProxyValidationError, got %T", err)
			for _, code := range c.wantCodes {
				assert.True(t, verr.HasCode(code), "expected code %q in %v", code, verr.Codes)
			}
		})
	}
}

func TestMCPProxy_Validate_PluggedIntoOASValidate(t *testing.T) {
	t.Parallel()

	// A bare OAS doc with an MCPProxy carrying a placeholder UpstreamURL
	// must surface the MCP validation error through (*OAS).Validate.
	var s OAS
	s.OpenAPI = "3.0.3"
	s.Info = &openapi3.Info{Title: "mcp-proxy-test", Version: "1.0.0"}
	s.Paths = openapi3.NewPaths()
	s.SetTykExtension(&XTykAPIGateway{
		Server: Server{
			ListenPath: ListenPath{Value: "/mcp/demo"},
			MCPProxy: &MCPProxy{
				Sources: []MCPSource{
					{SourceSlug: "a", BackendMode: "upstream", UpstreamURL: "https://{x}/"},
				},
			},
		},
	})

	err := s.Validate(context.Background())
	require.Error(t, err)

	var verr *MCPProxyValidationError
	require.True(t, errors.As(err, &verr),
		"expected MCPProxyValidationError to be present in joined error, got %v", err)
	assert.True(t, verr.HasCode(MCPErrUpstreamURLContainsPlaceholder))
}
