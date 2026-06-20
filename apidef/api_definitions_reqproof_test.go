package apidef

import (
	"bytes"
	"encoding/base64"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

// Verifies: SYS-REQ-104, SW-REQ-080
// SW-REQ-080:nominal:nominal
// SW-REQ-080:boundary:nominal
// SW-REQ-080:error_handling:nominal
// SW-REQ-080:error_handling:negative
// SW-REQ-080:determinism:nominal
func TestAPIDefinitionReqProof_CoreHelperClassifiers(t *testing.T) {
	t.Run("headers and rate limit helpers classify enabled shape", func(t *testing.T) {
		assert.True(t, (&HeaderInjectionMeta{AddHeaders: map[string]string{"X-Test": "yes"}}).Enabled())
		assert.True(t, (&HeaderInjectionMeta{DeleteHeaders: []string{"X-Test"}}).Enabled())
		assert.False(t, (&HeaderInjectionMeta{Disabled: true, AddHeaders: map[string]string{"X-Test": "yes"}}).Enabled())
		assert.False(t, (&HeaderInjectionMeta{}).Enabled())

		assert.True(t, (&RateLimitMeta{Rate: 10, Per: 60}).Valid())
		require.NoError(t, (&RateLimitMeta{Rate: 10, Per: 60}).Err())

		for _, meta := range []*RateLimitMeta{
			nil,
			{Disabled: true, Rate: 10, Per: 60},
			{Rate: 10, Per: 0},
			{Rate: 0, Per: 60},
		} {
			assert.False(t, meta.Valid())
			require.Error(t, meta.Err())
		}
	})

	t.Run("routing and extended path helpers preserve owned fields", func(t *testing.T) {
		options := NewRoutingTriggerOptions()
		assert.NotNil(t, options.HeaderMatches)
		assert.NotNil(t, options.QueryValMatches)
		assert.NotNil(t, options.PathPartMatches)
		assert.NotNil(t, options.SessionMetaMatches)
		assert.NotNil(t, options.RequestContextMatches)
		assert.True(t, options.PayloadMatches.Empty())

		paths := ExtendedPathsSet{
			Ignored:             []EndPointMeta{{Path: "/old"}},
			TransformJQ:         []TransformJQMeta{{Path: "/jq"}},
			TransformJQResponse: []TransformJQMeta{{Path: "/jq-response"}},
			PersistGraphQL:      []PersistGraphQLMeta{{Path: "/graphql"}},
			RateLimit:           []RateLimitMeta{{Path: "/rate", Rate: 1, Per: 1}},
		}
		paths.Clear()

		assert.Empty(t, paths.Ignored)
		assert.Empty(t, paths.RateLimit)
		assert.Equal(t, []TransformJQMeta{{Path: "/jq"}}, paths.TransformJQ)
		assert.Equal(t, []TransformJQMeta{{Path: "/jq-response"}}, paths.TransformJQResponse)
		assert.Equal(t, []PersistGraphQLMeta{{Path: "/graphql"}}, paths.PersistGraphQL)
	})

	t.Run("version and discovery helpers return explicit effective values", func(t *testing.T) {
		assert.Equal(t, "v1", (&VersionDefinition{Name: "v1", Default: Self}).ResolvedDefault())
		assert.Equal(t, "v2", (&VersionDefinition{Name: "v1", Default: "v2"}).ResolvedDefault())

		version := &VersionInfo{
			GlobalHeaders:         map[string]string{"X-A": "1"},
			GlobalHeadersRemove:   []string{"X-B"},
			GlobalResponseHeaders: map[string]string{"X-C": "2"},
			UseExtendedPaths:      true,
			ExtendedPaths: ExtendedPathsSet{
				TransformHeader:         []HeaderInjectionMeta{{AddHeaders: map[string]string{"X-Req": "1"}}},
				TransformResponseHeader: []HeaderInjectionMeta{{DeleteHeaders: []string{"X-Res"}}},
			},
		}
		assert.True(t, version.GlobalHeadersEnabled())
		assert.True(t, version.GlobalResponseHeadersEnabled())
		assert.True(t, version.HasEndpointReqHeader())
		assert.True(t, version.HasEndpointResHeader())

		version.GlobalHeadersDisabled = true
		version.GlobalResponseHeadersDisabled = true
		version.UseExtendedPaths = false
		assert.False(t, version.GlobalHeadersEnabled())
		assert.False(t, version.GlobalResponseHeadersEnabled())
		assert.False(t, version.HasEndpointReqHeader())
		assert.False(t, version.HasEndpointResHeader())

		timeout, enabled := (&ServiceDiscoveryConfiguration{CacheTimeout: 30}).CacheOptions()
		assert.EqualValues(t, 30, timeout)
		assert.True(t, enabled)
		_, enabled = (&ServiceDiscoveryConfiguration{CacheDisabled: true}).CacheOptions()
		assert.False(t, enabled)
	})

	t.Run("expiry helpers distinguish absent, future, past, and unparsed expiries", func(t *testing.T) {
		assert.False(t, (&VersionInfo{}).Expired())
		assert.False(t, (&VersionInfo{Expires: "-1"}).Expired())
		assert.True(t, (&VersionInfo{Expires: "unparsed"}).Expired())
		assert.True(t, (&VersionInfo{Expires: "past", ExpiresTs: time.Now().Add(-time.Hour)}).Expired())

		future := time.Now().Add(time.Hour)
		version := &VersionInfo{Expires: "future", ExpiresTs: future}
		assert.False(t, version.Expired())
		assert.Equal(t, future, version.ExpiryTime())
		assert.True(t, (&VersionInfo{Expires: "past", ExpiresTs: time.Now().Add(-time.Hour)}).ExpiryTime().IsZero())
	})

	t.Run("upstream auth and auth source helpers require explicit enablement", func(t *testing.T) {
		assert.False(t, (&UpstreamAuth{Enabled: true}).IsEnabled())
		assert.True(t, (&UpstreamAuth{Enabled: true, BasicAuth: UpstreamBasicAuth{Enabled: true}}).IsEnabled())
		assert.True(t, (&UpstreamAuth{Enabled: true, OAuth: UpstreamOAuth{Enabled: true}}).IsEnabled())
		assert.False(t, (&UpstreamAuth{Enabled: false, BasicAuth: UpstreamBasicAuth{Enabled: true}}).IsEnabled())
		assert.True(t, UpstreamOAuth{Enabled: true}.IsEnabled())
		assert.False(t, UpstreamOAuth{}.IsEnabled())

		assert.True(t, AuthSource{Enabled: true, Name: "Authorization"}.IsEnabled())
		assert.Equal(t, "Authorization", AuthSource{Enabled: true, Name: "Authorization"}.AuthKeyName())
		assert.Empty(t, AuthSource{Name: "Authorization"}.AuthKeyName())
	})
}

// Verifies: SYS-REQ-104, SW-REQ-080
// SW-REQ-080:nominal:nominal
// SW-REQ-080:boundary:boundary
// SW-REQ-080:error_handling:negative
// SW-REQ-080:determinism:nominal
func TestAPIDefinitionReqProof_PersistenceAndAPIShapeHelpers(t *testing.T) {
	t.Run("database encode and decode round trip key maps and validation schemas", func(t *testing.T) {
		api := APIDefinition{
			VersionData: VersionData{Versions: map[string]VersionInfo{
				"v 1": {
					Name: "v 1",
					ExtendedPaths: ExtendedPathsSet{ValidateJSON: []ValidatePathMeta{{
						Path:   "/pets",
						Method: "POST",
						Schema: map[string]interface{}{
							"type":     "object",
							"required": []interface{}{"id"},
						},
					}}},
				},
			}},
			UpstreamCertificates: map[string]string{"api.example.com:443": "cert-a"},
			PinnedPublicKeys:     map[string]string{"pin.example.com": "pin-a"},
			AuthConfigs:          map[string]AuthConfig{AuthTokenType: {AuthHeaderName: "Authorization"}},
		}

		api.EncodeForDB()

		encodedVersion := base64.StdEncoding.EncodeToString([]byte("v 1"))
		encodedUpstream := base64.StdEncoding.EncodeToString([]byte("api.example.com:443"))
		encodedPin := base64.StdEncoding.EncodeToString([]byte("pin.example.com"))
		require.Contains(t, api.VersionData.Versions, encodedVersion)
		require.Contains(t, api.UpstreamCertificates, encodedUpstream)
		require.Contains(t, api.PinnedPublicKeys, encodedPin)
		assert.Equal(t, encodedVersion, api.VersionData.Versions[encodedVersion].Name)
		assert.NotEmpty(t, api.VersionData.Versions[encodedVersion].ExtendedPaths.ValidateJSON[0].SchemaB64)
		assert.Equal(t, "Authorization", api.Auth.AuthHeaderName)

		api.DecodeFromDB()

		require.Contains(t, api.VersionData.Versions, "v 1")
		assert.Equal(t, "v 1", api.VersionData.Versions["v 1"].Name)
		assert.Equal(t, map[string]string{"api.example.com:443": "cert-a"}, api.UpstreamCertificates)
		assert.Equal(t, map[string]string{"pin.example.com": "pin-a"}, api.PinnedPublicKeys)
		decodedSchema := api.VersionData.Versions["v 1"].ExtendedPaths.ValidateJSON[0]
		assert.Empty(t, decodedSchema.SchemaB64)
		assert.Equal(t, "object", decodedSchema.Schema["type"])
		assert.Equal(t, []interface{}{"id"}, decodedSchema.Schema["required"])
	})

	t.Run("decode keeps legacy unencoded keys and backfills auth configs", func(t *testing.T) {
		api := APIDefinition{
			UseStandardAuth:            true,
			EnableJWT:                  true,
			Auth:                       AuthConfig{AuthHeaderName: "X-Legacy"},
			UpstreamCertificates:       map[string]string{"plain-domain": "cert"},
			PinnedPublicKeys:           map[string]string{"plain-pin": "pin"},
			VersionData:                VersionData{Versions: map[string]VersionInfo{"legacy": {Name: "legacy"}}},
			CertificatePinningDisabled: false,
		}

		api.DecodeFromDB()

		assert.Equal(t, "legacy", api.VersionData.Versions["legacy"].Name)
		assert.Equal(t, map[string]string{"plain-domain": "cert"}, api.UpstreamCertificates)
		assert.Equal(t, map[string]string{"plain-pin": "pin"}, api.PinnedPublicKeys)
		assert.Equal(t, "X-Legacy", api.AuthConfigs[AuthTokenType].AuthHeaderName)
		assert.Equal(t, "X-Legacy", api.AuthConfigs[JWTType].AuthHeaderName)
	})

	t.Run("API identity, domain, protocol, and versioning helpers expose shape flags", func(t *testing.T) {
		api := &APIDefinition{Domain: "api.example.com"}
		assert.Equal(t, "api.example.com", api.GetAPIDomain())
		api.DomainDisabled = true
		assert.Empty(t, api.GetAPIDomain())

		api.SetProtocol(JsonRPC20, AppProtocolMCP)
		assert.True(t, api.IsMCP())
		api.ApplicationProtocol = ""
		api.MarkAsMCP()
		assert.Equal(t, JsonRPC20, api.JsonRpcVersion)
		assert.True(t, api.IsMCP())

		api.APIID = "child"
		api.VersionDefinition = VersionDefinition{BaseID: "base"}
		assert.True(t, api.IsChildAPI())
		api.APIID = "base"
		api.VersionDefinition = VersionDefinition{BaseID: "base", Versions: map[string]string{"v2": "child"}}
		assert.True(t, api.IsBaseAPI())
		assert.False(t, api.IsBaseAPIWithVersioning())
		api.VersionDefinition.Enabled = true
		api.VersionDefinition.Name = "v1"
		assert.True(t, api.IsBaseAPIWithVersioning())

		api.GenerateAPIID()
		assert.NotEmpty(t, api.APIID)
	})

	t.Run("scope helpers choose legacy, JWT, or OIDC shape", func(t *testing.T) {
		legacy := &APIDefinition{
			JWTScopeClaimName:       "legacy-scope",
			JWTScopeToPolicyMapping: map[string]string{"read": "legacy-policy"},
		}
		assert.Equal(t, "legacy-scope", legacy.GetScopeClaimName())
		assert.Equal(t, map[string]string{"read": "legacy-policy"}, legacy.GetScopeToPolicyMapping())

		jwt := &APIDefinition{Scopes: Scopes{JWT: ScopeClaim{
			ScopeClaimName: "jwt-scope",
			ScopeToPolicy:  map[string]string{"read": "jwt-policy"},
		}}}
		assert.Equal(t, "jwt-scope", jwt.GetScopeClaimName())
		assert.Equal(t, map[string]string{"read": "jwt-policy"}, jwt.GetScopeToPolicyMapping())

		oidc := &APIDefinition{UseOpenID: true, Scopes: Scopes{OIDC: ScopeClaim{
			ScopeClaimName: "oidc-scope",
			ScopeToPolicy:  map[string]string{"read": "oidc-policy"},
		}}}
		assert.Equal(t, "oidc-scope", oidc.GetScopeClaimName())
		assert.Equal(t, map[string]string{"read": "oidc-policy"}, oidc.GetScopeToPolicyMapping())
	})

	t.Run("dummy API returns initialized collection shapes", func(t *testing.T) {
		first := DummyAPI()
		second := DummyAPI()

		assert.Equal(t, first.GraphQL.Proxy.Features.UseImmutableHeaders, second.GraphQL.Proxy.Features.UseImmutableHeaders)
		assert.True(t, first.VersionData.NotVersioned)
		assert.NotNil(t, first.ConfigData)
		assert.NotNil(t, first.PinnedPublicKeys)
		assert.NotNil(t, first.UpstreamCertificates)
		assert.NotNil(t, first.Scopes.JWT.ScopeToPolicy)
		assert.NotNil(t, first.CustomMiddleware.IdExtractor.ExtractorConfig)
		assert.True(t, first.Proxy.DisableStripSlash)
		assert.Contains(t, first.CORS.AllowedMethods, "GET")
		assert.NotEmpty(t, first.ErrorOverrides)
	})
}

// Verifies: SYS-REQ-104, SW-REQ-080
// SW-REQ-080:nominal:nominal
// SW-REQ-080:boundary:boundary
// SW-REQ-080:error_handling:negative
// SW-REQ-080:determinism:nominal
func TestAPIDefinitionReqProof_MatchersTemplatesAndScanners(t *testing.T) {
	t.Run("regex map helpers match normal, reverse, empty, and invalid patterns", func(t *testing.T) {
		assert.True(t, StringRegexMap{}.Empty())
		assert.False(t, StringRegexMap{MatchPattern: "pet"}.Empty())
		assert.False(t, StringRegexMap{Reverse: true}.Empty())

		var uninitialized StringRegexMap
		assert.Empty(t, uninitialized.Check("pet"))
		matched, submatch := uninitialized.FindStringSubmatch("pet")
		assert.False(t, matched)
		assert.Empty(t, submatch)

		matcher := &StringRegexMap{MatchPattern: `pet-(\d+)`}
		require.NoError(t, matcher.Init())
		assert.Equal(t, "pet-123", matcher.Check("pet-123"))
		matched, submatch = matcher.FindStringSubmatch("pet-123")
		assert.True(t, matched)
		assert.Equal(t, []string{"pet-123", "123"}, submatch)
		matched, all := matcher.FindAllStringSubmatch("pet-123 pet-456", -1)
		assert.True(t, matched)
		assert.Len(t, all, 2)

		reverse := &StringRegexMap{MatchPattern: `blocked`, Reverse: true}
		require.NoError(t, reverse.Init())
		matched, _ = reverse.FindStringSubmatch("allowed")
		assert.True(t, matched)
		matched, _ = reverse.FindAllStringSubmatch("blocked", -1)
		assert.False(t, matched)

		require.Error(t, (&StringRegexMap{MatchPattern: `[`}).Init())
	})

	t.Run("template helpers marshal JSON and XML deterministically", func(t *testing.T) {
		var jsonOut bytes.Buffer
		require.NoError(t, templateMustClone(t).ExecuteTemplate(&jsonOut, "json", map[string]interface{}{"name": "tyk"}))
		assert.Equal(t, `{"name":"tyk"}`, jsonOut.String())

		var xmlOut bytes.Buffer
		require.NoError(t, templateMustClone(t).ExecuteTemplate(&xmlOut, "xml", map[string]interface{}{"name": "tyk"}))
		assert.Contains(t, xmlOut.String(), "<name>tyk</name>")
	})

	t.Run("event handler scans copy valid input and reject unmarshalable input", func(t *testing.T) {
		webhookInput := map[string]interface{}{
			"disabled":      true,
			"id":            "hook-id",
			"name":          "hook",
			"method":        "POST",
			"target_path":   "https://example.com/hook",
			"template_path": "/tmp/hook.tmpl",
			"header_map":    map[string]string{"X-Hook": "yes"},
			"event_timeout": float64(7),
		}
		var webhook WebHookHandlerConf
		require.NoError(t, webhook.Scan(webhookInput))
		assert.True(t, webhook.Disabled)
		assert.Equal(t, "hook-id", webhook.ID)
		assert.EqualValues(t, 7, webhook.EventTimeout)

		var jsvm JSVMEventHandlerConf
		require.NoError(t, jsvm.Scan(map[string]interface{}{"disabled": true, "id": "js-id", "name": "Handle", "path": "/tmp/handler.js"}))
		assert.Equal(t, "Handle", jsvm.MethodName)

		var logHandler LogEventHandlerConf
		require.NoError(t, logHandler.Scan(map[string]interface{}{"disabled": true, "prefix": "audit"}))
		assert.Equal(t, "audit", logHandler.Prefix)

		require.Error(t, webhook.Scan(map[string]interface{}{"bad": make(chan int)}))
		require.Error(t, jsvm.Scan(map[string]interface{}{"bad": make(chan int)}))
		require.Error(t, logHandler.Scan(map[string]interface{}{"bad": make(chan int)}))
	})

	t.Run("JWK cache timeout and uptime commands keep explicit values", func(t *testing.T) {
		assert.EqualValues(t, 15, (&JWK{CacheTimeout: tyktime.ReadableDuration(15 * time.Second)}).GetCacheTimeoutSeconds(60))
		assert.EqualValues(t, 60, (&JWK{}).GetCacheTimeoutSeconds(60))
		assert.EqualValues(t, 60, (&JWK{CacheTimeout: tyktime.ReadableDuration(-time.Second)}).GetCacheTimeoutSeconds(60))

		check := &HostCheckObject{}
		check.AddCommand("tcp", "open")
		check.AddCommand("banner", "ok")
		assert.Equal(t, []CheckCommand{{Name: "tcp", Message: "open"}, {Name: "banner", Message: "ok"}}, check.Commands)
	})
}

func templateMustClone(t *testing.T) *template.Template {
	t.Helper()

	clone, err := Template.Clone()
	require.NoError(t, err)
	_, err = clone.New("json").Parse(`{{ jsonMarshal . }}`)
	require.NoError(t, err)
	_, err = clone.New("xml").Parse(`{{ xmlMarshal . }}`)
	require.NoError(t, err)
	return clone
}
