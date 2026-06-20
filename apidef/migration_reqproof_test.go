package apidef

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/event"
)

// Verifies: SYS-REQ-104, SW-REQ-085
// SW-REQ-085:nominal:nominal
// SW-REQ-085:boundary:boundary
// SW-REQ-085:error_handling:negative
// SW-REQ-085:determinism:nominal
func TestMigrationReqProof_VersionEndpointAndCacheMigration(t *testing.T) {
	t.Run("versioning rejects already migrated definitions and deterministically splits child versions", func(t *testing.T) {
		alreadyMigrated := oldTestAPI()
		alreadyMigrated.VersionDefinition.Enabled = true
		_, err := alreadyMigrated.MigrateVersioning()
		require.ErrorIs(t, err, ErrMigrationNewVersioningEnabled)

		base := oldTestAPI()
		firstVersions, err := base.MigrateVersioning()
		require.NoError(t, err)
		require.Len(t, firstVersions, 1)

		assert.Equal(t, v1, base.VersionName)
		assert.Equal(t, exp1, base.Expiration)
		assert.Equal(t, VersionDefinition{
			Enabled:             true,
			Name:                v1,
			Default:             Self,
			Location:            URLLocation,
			Key:                 key,
			StripVersioningData: true,
			Versions:            map[string]string{v2: firstVersions[0].APIID},
		}, base.VersionDefinition)
		assert.True(t, base.VersionData.NotVersioned)
		assert.Contains(t, base.VersionData.Versions, "")

		secondBase := oldTestAPI()
		secondVersions, err := secondBase.MigrateVersioning()
		require.NoError(t, err)
		require.Len(t, secondVersions, 1)
		assert.Equal(t, firstVersions[0].VersionName, secondVersions[0].VersionName)
		assert.Equal(t, firstVersions[0].Proxy.ListenPath, secondVersions[0].Proxy.ListenPath)
		assert.NotEqual(t, firstVersions[0].APIID, secondVersions[0].APIID)
	})

	t.Run("endpoint method-action maps split into method-specific metadata and mock responses", func(t *testing.T) {
		api := APIDefinition{VersionData: VersionData{Versions: map[string]VersionInfo{
			"": {
				ExtendedPaths: ExtendedPathsSet{
					WhiteList: []EndPointMeta{{
						Path:       "/pets",
						IgnoreCase: true,
						MethodActions: map[string]EndpointMethodMeta{
							http.MethodPost: {Action: Reply, Code: http.StatusCreated, Data: "created", Headers: map[string]string{"X-Test": "yes"}},
							http.MethodGet:  {Action: NoAction, Code: http.StatusOK},
						},
					}},
					BlackList: []EndPointMeta{{
						Path:     "/blocked",
						Disabled: true,
						MethodActions: map[string]EndpointMethodMeta{
							http.MethodDelete: {Action: Reply, Code: http.StatusForbidden, Data: "blocked"},
						},
					}},
					Ignored: []EndPointMeta{{
						Path: "/ignored",
						MethodActions: map[string]EndpointMethodMeta{
							http.MethodPatch: {Action: Reply, Code: http.StatusAccepted, Data: "ignored"},
						},
					}},
				},
			},
		}}}

		api.MigrateEndpointMeta()
		vInfo := api.VersionData.Versions[""]

		assert.Equal(t, []EndPointMeta{
			{Path: "/pets", Method: http.MethodGet, IgnoreCase: true},
			{Path: "/pets", Method: http.MethodPost, IgnoreCase: true},
		}, vInfo.ExtendedPaths.WhiteList)
		assert.Equal(t, []EndPointMeta{{Path: "/blocked", Method: http.MethodDelete, Disabled: true}}, vInfo.ExtendedPaths.BlackList)
		assert.Equal(t, []EndPointMeta{{Path: "/ignored", Method: http.MethodPatch}}, vInfo.ExtendedPaths.Ignored)
		assert.ElementsMatch(t, []MockResponseMeta{
			{Path: "/pets", Method: http.MethodPost, IgnoreCase: true, Code: http.StatusCreated, Body: "created", Headers: map[string]string{"X-Test": "yes"}},
			{Path: "/blocked", Method: http.MethodDelete, Disabled: true, Code: http.StatusForbidden, Body: "blocked"},
			{Path: "/ignored", Method: http.MethodPatch, Code: http.StatusAccepted, Body: "ignored"},
		}, vInfo.ExtendedPaths.MockResponse)
	})

	t.Run("simple cache paths migrate into method-specific advanced cache entries", func(t *testing.T) {
		api := APIDefinition{
			CacheOptions: CacheOptions{
				EnableCache:            true,
				CacheTimeout:           120,
				CacheOnlyResponseCodes: []int{200, 404},
			},
			VersionData: VersionData{Versions: map[string]VersionInfo{
				"": {
					UseExtendedPaths: true,
					ExtendedPaths: ExtendedPathsSet{
						Cached: []string{"/pets"},
						AdvanceCacheConfig: []CacheMeta{{
							Path: "/existing", Method: http.MethodPost, Timeout: 30,
						}},
					},
				},
			}},
		}

		api.MigrateCachePlugin()

		assert.Nil(t, api.VersionData.Versions[""].ExtendedPaths.Cached)
		assert.Equal(t, []CacheMeta{
			{Path: "/pets", Method: http.MethodGet, Timeout: 120, CacheOnlyResponseCodes: []int{200, 404}},
			{Path: "/pets", Method: http.MethodHead, Timeout: 120, CacheOnlyResponseCodes: []int{200, 404}},
			{Path: "/pets", Method: http.MethodOptions, Timeout: 120, CacheOnlyResponseCodes: []int{200, 404}},
			{Path: "/existing", Method: http.MethodPost, Timeout: 30},
		}, api.VersionData.Versions[""].ExtendedPaths.AdvanceCacheConfig)

		assert.Equal(t, CacheMeta{Disabled: true, Path: "/off", Method: http.MethodGet, Timeout: DefaultCacheTimeout}, createAdvancedCacheConfig(CacheOptions{}, "/off", http.MethodGet))
	})
}

// Verifies: SYS-REQ-104, SW-REQ-085
// SW-REQ-085:nominal:nominal
// SW-REQ-085:boundary:boundary
// SW-REQ-085:error_handling:negative
// SW-REQ-085:determinism:nominal
func TestMigrationReqProof_AuthenticationFlagsAndTopLevelMigration(t *testing.T) {
	t.Run("authentication migration keeps only enabled auth modes and names configs", func(t *testing.T) {
		api := APIDefinition{
			UseKeylessAccess:        false,
			UseStandardAuth:         true,
			EnableJWT:               true,
			EnableSignatureChecking: true,
			UseBasicAuth:            true,
			CustomPluginAuthEnabled: true,
			UseOauth2:               true,
			ExternalOAuth:           ExternalOAuth{Enabled: true},
			UseOpenID:               true,
			AuthConfigs: map[string]AuthConfig{
				AuthTokenType:     {},
				JWTType:           {},
				HMACType:          {},
				BasicType:         {},
				CoprocessType:     {},
				OAuthType:         {},
				ExternalOAuthType: {},
				OIDCType:          {},
			},
		}

		api.MigrateAuthentication()

		for authType, config := range api.AuthConfigs {
			assert.Equal(t, authType, config.Name)
		}
		assert.Contains(t, api.AuthConfigs, AuthTokenType)
		assert.Contains(t, api.AuthConfigs, JWTType)
		assert.Contains(t, api.AuthConfigs, HMACType)
		assert.Contains(t, api.AuthConfigs, BasicType)
		assert.Contains(t, api.AuthConfigs, CoprocessType)
		assert.Contains(t, api.AuthConfigs, OAuthType)
		assert.Contains(t, api.AuthConfigs, ExternalOAuthType)
		assert.Contains(t, api.AuthConfigs, OIDCType)

		api.CustomMiddleware.Driver = GoPluginDriver
		api.MigrateAuthentication()
		assert.NotContains(t, api.AuthConfigs, CoprocessType)

		keyless := APIDefinition{UseKeylessAccess: true, AuthConfigs: map[string]AuthConfig{AuthTokenType: {}}}
		keyless.MigrateAuthentication()
		assert.Empty(t, keyless.AuthConfigs)
	})

	t.Run("top-level migration applies legacy helper rewrites before version split", func(t *testing.T) {
		api := oldTestAPI()
		api.UseOauth2 = false
		api.UseGoPluginAuth = true
		api.EnableCoProcessAuth = true
		api.AuthConfigs[CoprocessType] = AuthConfig{}
		api.AuthConfigs[OAuthType] = AuthConfig{}
		api.ResponseProcessors = []ResponseProcessor{
			{Name: ResponseProcessorResponseBodyTransform},
			{Name: "keep"},
		}
		api.JWTScopeClaimName = "scope"
		api.JWTScopeToPolicyMapping = map[string]string{"read": "policy-read"}
		api.GlobalRateLimit = GlobalRateLimit{Rate: 10, Per: 60}
		api.EnableIpWhiteListing = true
		api.AllowedIPs = []string{"127.0.0.1"}

		versions, err := api.Migrate()
		require.NoError(t, err)
		require.Len(t, versions, 1)

		assert.True(t, api.CustomPluginAuthEnabled)
		assert.False(t, api.UseGoPluginAuth)
		assert.False(t, api.EnableCoProcessAuth)
		assert.True(t, api.CustomMiddlewareBundleDisabled)
		assert.True(t, api.ConfigDataDisabled)
		assert.True(t, api.UpstreamCertificatesDisabled)
		assert.True(t, api.CertificatePinningDisabled)
		assert.True(t, api.TagsDisabled)
		assert.True(t, api.CustomMiddleware.AuthCheck.Disabled)
		assert.True(t, api.CustomMiddleware.IdExtractor.Disabled)
		assert.True(t, api.DomainDisabled)
		assert.False(t, api.GlobalRateLimit.Disabled)
		assert.False(t, api.IPAccessControlDisabled)
		assert.Equal(t, []ResponseProcessor{{Name: "keep"}}, api.ResponseProcessors)
		assert.Equal(t, ScopeClaim{ScopeClaimName: "scope", ScopeToPolicy: map[string]string{"read": "policy-read"}}, api.Scopes.JWT)
		assert.Empty(t, api.JWTScopeClaimName)
		assert.Nil(t, api.JWTScopeToPolicyMapping)
		assert.Contains(t, api.AuthConfigs, CoprocessType)
		assert.NotContains(t, api.AuthConfigs, OAuthType)
		assert.True(t, api.VersionData.NotVersioned)
	})

	t.Run("disabled flag migration initializes disabled compatibility defaults", func(t *testing.T) {
		api := APIDefinition{
			CustomMiddleware: MiddlewareSection{
				Pre:         []MiddlewareDefinition{{Name: "pre"}},
				PostKeyAuth: []MiddlewareDefinition{{Name: "post-key"}},
				Post:        []MiddlewareDefinition{{Name: "post"}},
				Response:    []MiddlewareDefinition{{Name: "response"}},
			},
			VersionData: VersionData{Versions: map[string]VersionInfo{"": {
				ExtendedPaths: ExtendedPathsSet{
					Virtual:  []VirtualMeta{{Path: "/virtual"}},
					GoPlugin: []GoPluginMeta{{Path: "/plugin"}},
				},
			}}},
			EventHandlers: EventHandlerMetaConfig{Events: map[TykEvent][]EventHandlerTriggerConfig{
				event.QuotaExceeded: {{Handler: event.WebHookHandler, HandlerMeta: map[string]interface{}{"target_path": "https://example.com"}}},
			}},
		}

		api.SetDisabledFlags()

		assert.True(t, api.CustomMiddleware.AuthCheck.Disabled)
		assert.True(t, api.CustomMiddleware.Pre[0].Disabled)
		assert.True(t, api.CustomMiddleware.PostKeyAuth[0].Disabled)
		assert.True(t, api.CustomMiddleware.Post[0].Disabled)
		assert.True(t, api.CustomMiddleware.Response[0].Disabled)
		assert.True(t, api.CustomMiddleware.IdExtractor.Disabled)
		assert.True(t, api.TagsDisabled)
		assert.True(t, api.UpstreamCertificatesDisabled)
		assert.True(t, api.CertificatePinningDisabled)
		assert.True(t, api.DomainDisabled)
		assert.True(t, api.CustomMiddlewareBundleDisabled)
		assert.True(t, api.ConfigDataDisabled)
		assert.True(t, api.Proxy.ServiceDiscovery.CacheDisabled)
		assert.True(t, api.UptimeTests.Config.ServiceDiscovery.CacheDisabled)
		assert.True(t, api.VersionData.Versions[""].ExtendedPaths.Virtual[0].Disabled)
		assert.True(t, api.VersionData.Versions[""].ExtendedPaths.GoPlugin[0].Disabled)
		assert.True(t, api.GlobalRateLimit.Disabled)
		assert.True(t, api.DoNotTrack)
		assert.True(t, api.ErrorOverridesDisabled)
		assert.Equal(t, true, api.EventHandlers.Events[event.QuotaExceeded][0].HandlerMeta["disabled"])
	})

	t.Run("rate-limit and IP access-control boundary helpers classify empty and enabled inputs", func(t *testing.T) {
		api := APIDefinition{}
		api.migrateGlobalRateLimit()
		assert.True(t, api.GlobalRateLimit.Disabled)

		api.GlobalRateLimit = GlobalRateLimit{Rate: 1, Per: 1}
		api.migrateGlobalRateLimit()
		assert.False(t, api.GlobalRateLimit.Disabled)

		api = APIDefinition{EnableIpBlacklisting: true, BlacklistedIPs: []string{"10.0.0.1"}}
		api.migrateIPAccessControl()
		assert.False(t, api.IPAccessControlDisabled)

		api = APIDefinition{EnableIpWhiteListing: true}
		api.migrateIPAccessControl()
		assert.True(t, api.IPAccessControlDisabled)
	})
}
