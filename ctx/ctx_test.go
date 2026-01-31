package ctx_test

import (
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/uuid"
)

// Test for GetDefinition
func TestGetDefinition(t *testing.T) {
	apiDef := &apidef.APIDefinition{
		APIID: uuid.New(),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	assert.Nil(t, ctx.GetDefinition(req))

	ctx.SetDefinition(req, apiDef)
	cloned := ctx.GetDefinition(req)

	assert.Equal(t, apiDef, cloned)
}

// Test for GetOASDefinition
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
}

// Benchmark for GetDefinition
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

// Benchmark for GetOASDefinition
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

// TestContextKeyUniqueness verifies all context keys have unique values
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
		ctx.JsonRPCRouting:            "JsonRPCRouting",
		ctx.JSONRPCRequest:            "JSONRPCRequest",
		ctx.JSONRPCRoutingState:       "JSONRPCRoutingState",
	}

	seen := make(map[ctx.Key]bool)
	for key, name := range keys {
		if seen[key] {
			t.Errorf("Duplicate context key value %d for %s", key, name)
		}
		seen[key] = true
	}
}
