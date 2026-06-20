package ctx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

func setGlobalHashKeys(t *testing.T, hashKeys bool) {
	t.Helper()

	previous := config.Global
	config.Global = func() config.Config {
		return config.Config{HashKeys: hashKeys}
	}
	t.Cleanup(func() {
		config.Global = previous
	})
}

// Verifies: STK-REQ-037, SYS-REQ-125, SW-REQ-112
// SW-REQ-112:nominal:nominal
// SW-REQ-112:boundary:nominal
func TestGetDefinition(t *testing.T) {
	apiDef := &apidef.APIDefinition{
		APIID: uuid.New(),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	assert.Nil(t, ctx.GetDefinition(req))

	ctx.SetDefinition(req, apiDef)
	cloned := ctx.GetDefinition(req)

	assert.Equal(t, apiDef, cloned)
	assert.NotSame(t, apiDef, cloned)

	cloned.APIID = uuid.New()
	assert.NotEqual(t, cloned.APIID, ctx.GetDefinition(req).APIID)
}

// Verifies: STK-REQ-037, SYS-REQ-125, SW-REQ-112
// SW-REQ-112:nominal:nominal
// SW-REQ-112:boundary:nominal
func TestGetOASDefinition(t *testing.T) {
	oasDef := &oas.OAS{}
	oasDef.Info = &openapi3.Info{
		Title:   uuid.New(),
		Version: "1",
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	assert.Nil(t, ctx.GetOASDefinition(req))

	ctx.SetOASDefinition(req, oasDef)
	cloned := ctx.GetOASDefinition(req)

	assert.Equal(t, oasDef, cloned)
	assert.NotSame(t, oasDef, cloned)

	cloned.Info.Title = uuid.New()
	assert.NotEqual(t, cloned.Info.Title, ctx.GetOASDefinition(req).Info.Title)
}

func BenchmarkGetDefinition(b *testing.B) {
	apiDef := &apidef.APIDefinition{
		APIID: uuid.New(),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	ctx.SetDefinition(req, apiDef)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cloned := ctx.GetDefinition(req)
		assert.Equal(b, apiDef, cloned)
	}
}

func BenchmarkGetOASDefinition(b *testing.B) {
	oasDef := &oas.OAS{}
	oasDef.Info = &openapi3.Info{
		Title:   uuid.New(),
		Version: "1",
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	ctx.SetOASDefinition(req, oasDef)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cloned := ctx.GetOASDefinition(req)
		assert.Equal(b, oasDef, cloned)
	}
}

// Verifies: STK-REQ-037, SYS-REQ-125, SW-REQ-112
// SW-REQ-112:boundary:nominal
func TestContextKeyUniqueness(t *testing.T) {
	keys := map[ctx.Key]string{
		ctx.SessionData:               "SessionData",
		ctx.UpdateSession:             "UpdateSession",
		ctx.AuthToken:                 "AuthToken",
		ctx.HashedAuthToken:           "HashedAuthToken",
		ctx.VersionData:               "VersionData",
		ctx.VersionName:               "VersionName",
		ctx.VersionDefault:            "VersionDefault",
		ctx.OrgSessionContext:         "OrgSessionContext",
		ctx.ContextData:               "ContextData",
		ctx.RetainHost:                "RetainHost",
		ctx.TrackThisEndpoint:         "TrackThisEndpoint",
		ctx.DoNotTrackThisEndpoint:    "DoNotTrackThisEndpoint",
		ctx.UrlRewritePath:            "UrlRewritePath",
		ctx.InternalRedirectTarget:    "InternalRedirectTarget",
		ctx.RequestMethod:             "RequestMethod",
		ctx.OrigRequestURL:            "OrigRequestURL",
		ctx.LoopLevel:                 "LoopLevel",
		ctx.LoopLevelLimit:            "LoopLevelLimit",
		ctx.ThrottleLevel:             "ThrottleLevel",
		ctx.ThrottleLevelLimit:        "ThrottleLevelLimit",
		ctx.Trace:                     "Trace",
		ctx.CheckLoopLimits:           "CheckLoopLimits",
		ctx.UrlRewriteTarget:          "UrlRewriteTarget",
		ctx.TransformedRequestMethod:  "TransformedRequestMethod",
		ctx.Definition:                "Definition",
		ctx.RequestStatus:             "RequestStatus",
		ctx.GraphQLRequest:            "GraphQLRequest",
		ctx.GraphQLIsWebSocketUpgrade: "GraphQLIsWebSocketUpgrade",
		ctx.CacheOptions:              "CacheOptions",
		ctx.OASDefinition:             "OASDefinition",
		ctx.SelfLooping:               "SelfLooping",
		ctx.RequestStartTime:          "RequestStartTime",
		ctx.ErrorClassification:       "ErrorClassification",
		ctx.JsonRPCRouting:            "JsonRPCRouting",
		ctx.JSONRPCRequest:            "JSONRPCRequest",
		ctx.JSONRPCRoutingState:       "JSONRPCRoutingState",
		ctx.MCPRouting:                "MCPRouting",
		ctx.MCPMethod:                 "MCPMethod",
		ctx.MCPPrimitiveType:          "MCPPrimitiveType",
		ctx.MCPPrimitiveName:          "MCPPrimitiveName",
		ctx.JSONRPCErrorCode:          "JSONRPCErrorCode",
	}

	seen := make(map[ctx.Key]bool)
	for key, name := range keys {
		if seen[key] {
			t.Errorf("Duplicate context key value %d for %s", key, name)
		}
		seen[key] = true
	}
}

// Verifies: STK-REQ-037, SYS-REQ-125, SW-REQ-112
// SW-REQ-112:nominal:nominal
// SW-REQ-112:boundary:nominal
func TestErrorClassificationContext(t *testing.T) {
	t.Run("get returns nil when not set", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		assert.Nil(t, ctx.GetErrorClassification(req))
	})

	t.Run("get returns set value", func(t *testing.T) {
		errClass := errors.NewErrorClassification(errors.UCF, "connection_refused").
			WithSource("ReverseProxy").
			WithTarget("api.backend.com:443")

		req := httptest.NewRequest("GET", "http://example.com", nil)
		ctx.SetErrorClassification(req, errClass)
		result := ctx.GetErrorClassification(req)

		assert.Equal(t, errClass, result)
		assert.Equal(t, errors.UCF, result.Flag)
		assert.Equal(t, "connection_refused", result.Details)
		assert.Equal(t, "ReverseProxy", result.Source)
		assert.Equal(t, "api.backend.com:443", result.Target)
	})

	t.Run("TLS error with cert info", func(t *testing.T) {
		expiry := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
		errClass := errors.NewErrorClassification(errors.TLE, "tls_certificate_expired").
			WithSource("ReverseProxy").
			WithTarget("api.backend.com:443").
			WithTLSInfo(expiry, "CN=api.backend.com")

		req := httptest.NewRequest("GET", "http://example.com", nil)
		ctx.SetErrorClassification(req, errClass)
		result := ctx.GetErrorClassification(req)

		assert.Equal(t, errors.TLE, result.Flag)
		assert.Equal(t, expiry, result.TLSCertExpiry)
		assert.Equal(t, "CN=api.backend.com", result.TLSCertSubject)
	})
}

// Verifies: STK-REQ-037, SYS-REQ-125, SW-REQ-112
// SW-REQ-112:boundary:nominal
func TestErrorClassificationContext_NilSafe(t *testing.T) {
	t.Run("set nil does not panic", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		assert.NotPanics(t, func() {
			ctx.SetErrorClassification(req, nil)
		})
		// After setting nil, get should return nil
		assert.Nil(t, ctx.GetErrorClassification(req))
	})
}

// Verifies: STK-REQ-037, SYS-REQ-125, SW-REQ-112
// SW-REQ-112:nominal:nominal
// SW-REQ-112:boundary:nominal
// STK-REQ-037:error_handling:negative
// SYS-REQ-125:error_handling:negative
// SW-REQ-112:error_handling:negative
// MCDC SYS-REQ-125: request_context_operation_requested=F, request_context_result_determined=F => TRUE
// MCDC SYS-REQ-125: request_context_operation_requested=T, request_context_result_determined=T => TRUE
func TestSessionContext(t *testing.T) {
	t.Run("get returns nil when no session is present", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		assert.Nil(t, ctx.GetSession(req))
	})

	t.Run("set stores session auth token hash and update marker", func(t *testing.T) {
		setGlobalHashKeys(t, true)
		req := httptest.NewRequest("GET", "http://example.com", nil)
		session := &user.SessionState{KeyID: "token-1"}

		ctx.SetSession(req, session, true)

		require.Same(t, session, ctx.GetSession(req))
		assert.Equal(t, "token-1", ctx.GetAuthToken(req))
		assert.Equal(t, storage.HashKey("token-1", true), session.KeyHash())
		assert.True(t, session.IsModified())
	})

	t.Run("set fills empty session key from auth token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctx.AuthToken, "token-from-context"))
		session := &user.SessionState{}

		ctx.SetSession(req, session, false, true, false)

		require.Same(t, session, ctx.GetSession(req))
		assert.Equal(t, "token-from-context", session.KeyID)
		assert.Equal(t, storage.HashKey("token-from-context", true), session.KeyHash())
		assert.False(t, session.IsModified())
	})

	t.Run("get unmarshals compatible session value", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctx.SessionData, user.SessionState{OrgID: "org-1"}))

		got := ctx.GetSession(req)

		require.NotNil(t, got)
		assert.Equal(t, "org-1", got.OrgID)
	})

	t.Run("set nil session panics", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		require.PanicsWithValue(t, "setting a nil context SessionData", func() {
			ctx.SetSession(req, nil, false, true, false)
		})
	})
}

// Reproduces: KI-CTX-SESSION-HASH-OVERRIDE
// Verifies: SYS-REQ-125
// MCDC SYS-REQ-125: request_context_operation_requested=T, request_context_result_determined=F => FALSE
func TestKnownIssue_SetSessionSingleHashOverrideIgnored(t *testing.T) {
	setGlobalHashKeys(t, false)
	req := httptest.NewRequest("GET", "http://example.com", nil)
	session := &user.SessionState{KeyID: "token-override"}

	ctx.SetSession(req, session, false, true)

	assert.Equal(t, "token-override", session.KeyHash())
	assert.NotEqual(t, storage.HashKey("token-override", true), session.KeyHash())
}

// Verifies: STK-REQ-037, SYS-REQ-125, SW-REQ-112
// SW-REQ-112:nominal:nominal
// SW-REQ-112:boundary:nominal
func TestAuthTokenContext(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "missing auth token", value: nil, want: ""},
		{name: "wrong auth token type", value: 123, want: ""},
		{name: "string auth token", value: "abc123", want: "abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			if tt.value != nil {
				req = req.WithContext(context.WithValue(req.Context(), ctx.AuthToken, tt.value))
			}

			assert.Equal(t, tt.want, ctx.GetAuthToken(req))
		})
	}
}

// Verifies: STK-REQ-037, SYS-REQ-125, SW-REQ-112
// SW-REQ-112:nominal:nominal
// SW-REQ-112:boundary:nominal
func TestProtocolMetricContextGetters(t *testing.T) {
	tests := []struct {
		name      string
		key       ctx.Key
		value     any
		wrongType any
		get       func(*testing.T, *http.Request) any
		want      any
		zero      any
	}{
		{
			name:      "mcp method",
			key:       ctx.MCPMethod,
			value:     "tools/call",
			wrongType: 99,
			get: func(t *testing.T, req *http.Request) any {
				return ctx.GetMCPMethod(req)
			},
			want: "tools/call",
			zero: "",
		},
		{
			name:      "mcp primitive type",
			key:       ctx.MCPPrimitiveType,
			value:     "tool",
			wrongType: false,
			get: func(t *testing.T, req *http.Request) any {
				return ctx.GetMCPPrimitiveType(req)
			},
			want: "tool",
			zero: "",
		},
		{
			name:      "mcp primitive name",
			key:       ctx.MCPPrimitiveName,
			value:     "get_weather",
			wrongType: []string{"get_weather"},
			get: func(t *testing.T, req *http.Request) any {
				return ctx.GetMCPPrimitiveName(req)
			},
			want: "get_weather",
			zero: "",
		},
		{
			name:      "json rpc error code",
			key:       ctx.JSONRPCErrorCode,
			value:     -32601,
			wrongType: "-32601",
			get: func(t *testing.T, req *http.Request) any {
				return ctx.GetJSONRPCErrorCode(req)
			},
			want: -32601,
			zero: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			assert.Equal(t, tt.zero, tt.get(t, req))

			req = req.WithContext(context.WithValue(req.Context(), tt.key, tt.wrongType))
			assert.Equal(t, tt.zero, tt.get(t, req))

			req = req.WithContext(context.WithValue(req.Context(), tt.key, tt.value))
			assert.Equal(t, tt.want, tt.get(t, req))
		})
	}
}
