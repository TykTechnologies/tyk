package apidef

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/event"
)

const (
	dbID        = "dbID"
	apiID       = "apiID"
	listenPath  = "listenPath"
	baseTarget  = "base.com"
	baseAPIName = "base-api"
	v1Target    = "v1.com"
	v2Target    = "v2.com"
	v1          = "v1"
	v2          = "v2"
	exp1        = "exp1"
	exp2        = "exp2"
	key         = "version"
)

var testV1ExtendedPaths = ExtendedPathsSet{
	WhiteList: []EndPointMeta{
		{Method: http.MethodGet, Path: "/get1"},
	},
	TransformResponse: []TemplateMeta{
		{
			Method: http.MethodGet, Path: "/transform1",
			TemplateData: TemplateData{
				EnableSession:  true,
				Mode:           UseBlob,
				TemplateSource: `{"http_method":"{{.Method}}"}`,
				Input:          RequestJSON,
			}},
	},
}

var testV2ExtendedPaths = ExtendedPathsSet{
	WhiteList: []EndPointMeta{
		{Method: http.MethodGet, Path: "/get2"},
	},
	TransformResponse: []TemplateMeta{
		{
			Method: http.MethodGet, Path: "/transform2",
			TemplateData: TemplateData{
				EnableSession:  true,
				Mode:           UseBlob,
				TemplateSource: `{"http_method":"{{.Method}}"}`,
				Input:          RequestJSON,
			}},
	},
}

func oldTestAPI() APIDefinition {
	return APIDefinition{
		Id:        dbID,
		APIID:     apiID,
		Name:      baseAPIName,
		Active:    true,
		UseOauth2: true,
		Proxy:     ProxyConfig{TargetURL: baseTarget, ListenPath: listenPath},
		VersionDefinition: VersionDefinition{
			Location:  URLLocation,
			Key:       key,
			StripPath: true,
		},
		VersionData: VersionData{
			NotVersioned:   false,
			DefaultVersion: v1,
			Versions: map[string]VersionInfo{
				v1: {
					Expires:          exp1,
					UseExtendedPaths: true,
					ExtendedPaths:    testV1ExtendedPaths,
				},
				v2: {
					Expires:          exp2,
					UseExtendedPaths: true,
					ExtendedPaths:    testV2ExtendedPaths,
				},
			},
		},
		AuthConfigs: map[string]AuthConfig{
			AuthTokenType: {
				AuthHeaderName: "Authorization",
				UseParam:       true,
				ParamName:      "Authorization",
				UseCookie:      true,
				CookieName:     "Authorization",
			},
			OAuthType: {
				AuthHeaderName: "Authorization",
				UseParam:       true,
				ParamName:      "Authorization",
				UseCookie:      true,
				CookieName:     "Authorization",
			},
			JWTType: {
				AuthHeaderName: "Authorization",
				UseParam:       true,
				ParamName:      "Authorization",
				UseCookie:      true,
				CookieName:     "Authorization",
			},
			OIDCType: {
				AuthHeaderName: "Authorization",
				UseParam:       true,
				ParamName:      "Authorization",
				UseCookie:      true,
				CookieName:     "Authorization",
			},
			HMACType: {
				AuthHeaderName: "Authorization",
				UseParam:       true,
				ParamName:      "Authorization",
				UseCookie:      true,
				CookieName:     "Authorization",
			},
		},
		ResponseProcessors: []ResponseProcessor{
			{Name: ResponseProcessorResponseBodyTransform},
		},
	}
}

func TestAPIDefinition_MigrateVersioning(t *testing.T) {
	base := oldTestAPI()
	versions, err := base.MigrateVersioning()
	assert.NoError(t, err)

	expectedBase := base
	expectedBase.Expiration = exp1
	expectedBase.VersionData = VersionData{
		NotVersioned: true,
		Versions: map[string]VersionInfo{
			"": {
				UseExtendedPaths: true,
				ExtendedPaths:    testV1ExtendedPaths,
			},
		},
	}
	expectedBase.VersionDefinition = VersionDefinition{
		Enabled:             true,
		Name:                v1,
		Default:             Self,
		Location:            URLLocation,
		Key:                 key,
		StripVersioningData: true,
		Versions: map[string]string{
			v2: versions[0].APIID,
		},
	}

	assert.Equal(t, expectedBase, base)

	expectedVersion := oldTestAPI()
	expectedVersion.Id = ""
	expectedVersion.APIID = versions[0].APIID
	expectedVersion.Name += "-" + v2
	expectedVersion.VersionName = v2
	expectedVersion.Internal = true
	expectedVersion.Expiration = exp2
	expectedVersion.Proxy.ListenPath += "-" + v2 + "/"
	expectedVersion.VersionDefinition = VersionDefinition{BaseID: apiID}
	expectedVersion.VersionData = VersionData{
		NotVersioned: true,
		Versions: map[string]VersionInfo{
			"": {
				UseExtendedPaths: true,
				ExtendedPaths:    testV2ExtendedPaths,
			},
		},
	}

	assert.Len(t, versions, 1)
	assert.Equal(t, expectedVersion, versions[0])
}

func TestAPIDefinition_MigrateVersioning_Disabled(t *testing.T) {
	base := oldTestAPI()
	base.VersionData.NotVersioned = true

	t.Run("multiple versions", func(t *testing.T) {
		_, err := base.MigrateVersioning()
		assert.EqualError(t, err, "not migratable - if not versioned, there should be just one version info in versions map")
	})

	delete(base.VersionData.Versions, v2)

	t.Run("one version", func(t *testing.T) {
		versions, err := base.MigrateVersioning()
		assert.NoError(t, err)
		assert.Nil(t, versions)

		expectedBaseDefinition := VersionDefinition{}

		assert.Equal(t, expectedBaseDefinition, base.VersionDefinition)

		expectedBaseData := VersionData{
			NotVersioned: true,
			Versions: map[string]VersionInfo{
				"": {
					UseExtendedPaths: true,
					ExtendedPaths:    testV1ExtendedPaths,
				},
			},
		}

		assert.Equal(t, expectedBaseData, base.VersionData)
	})
}

func TestAPIDefinition_MigrateVersioning_DefaultEmpty(t *testing.T) {
	base := oldTestAPI()
	base.VersionData.DefaultVersion = ""

	versions, err := base.MigrateVersioning()
	assert.NoError(t, err)

	// v1 - selected as base even if default is empty, alphabetically v1>v2
	expectedBaseDefinition := VersionDefinition{
		Enabled:             true,
		Name:                v1,
		Default:             "", // should be empty
		Location:            URLLocation,
		Key:                 key,
		StripVersioningData: true,
		Versions: map[string]string{
			v2: versions[0].APIID,
		},
	}
	assert.Equal(t, expectedBaseDefinition, base.VersionDefinition)

	expectedBaseData := VersionData{
		NotVersioned: true,
		Versions: map[string]VersionInfo{
			"": {
				UseExtendedPaths: true,
				ExtendedPaths:    testV1ExtendedPaths,
			},
		},
	}
	assert.Equal(t, expectedBaseData, base.VersionData)

	// v2
	assert.Equal(t, apiID, versions[0].VersionDefinition.BaseID)
	versions[0].VersionDefinition.BaseID = ""
	assert.Empty(t, versions[0].VersionDefinition)

	expectedV2Data := VersionData{
		NotVersioned: true,
		Versions: map[string]VersionInfo{
			"": {
				UseExtendedPaths: true,
				ExtendedPaths:    testV2ExtendedPaths,
			},
		},
	}
	assert.Equal(t, expectedV2Data, versions[0].VersionData)

	t.Run("Default", func(t *testing.T) {
		base = oldTestAPI()
		base.VersionData.DefaultVersion = ""
		base.VersionData.Versions["Default"] = base.VersionData.Versions[v1]
		base.VersionData.Versions["Alpha"] = base.VersionData.Versions[v2]
		delete(base.VersionData.Versions, v1)
		delete(base.VersionData.Versions, v2)

		versions, err = base.MigrateVersioning()
		assert.NoError(t, err)

		assert.Equal(t, expectedBaseData, base.VersionData)

		assert.Len(t, versions, 1)
		assert.Contains(t, versions[0].Name, baseAPIName+"-Alpha")
	})
}

func TestAPIDefinition_MigrateVersioning_Expires(t *testing.T) {
	t.Run("version enabled", func(t *testing.T) {
		base := oldTestAPI()
		versions, err := base.MigrateVersioning()
		assert.NoError(t, err)

		assert.Equal(t, base.Expiration, exp1)
		assert.Equal(t, versions[0].Expiration, exp2)
	})

	t.Run("version disabled", func(t *testing.T) {
		base := oldTestAPI()
		delete(base.VersionData.Versions, v2)
		base.VersionData.NotVersioned = true
		versions, err := base.MigrateVersioning()
		assert.NoError(t, err)
		assert.Empty(t, versions)

		assert.Equal(t, base.Expiration, "")
		assert.Equal(t, base.VersionData.Versions[""].Expires, "")
	})
}

func TestAPIDefinition_MigrateVersioning_OverrideTarget(t *testing.T) {
	t.Run("base", func(t *testing.T) {
		base := oldTestAPI()
		vInfo := base.VersionData.Versions[v1]
		vInfo.OverrideTarget = v1Target
		base.VersionData.Versions[v1] = vInfo

		versions, err := base.MigrateVersioning()
		assert.NoError(t, err)

		assert.Equal(t, v1Target, base.Proxy.TargetURL)
		assert.Equal(t, baseTarget, versions[0].Proxy.TargetURL)
	})

	t.Run("version", func(t *testing.T) {
		base := oldTestAPI()
		vInfo := base.VersionData.Versions[v2]
		vInfo.OverrideTarget = v2Target
		base.VersionData.Versions[v2] = vInfo

		versions, err := base.MigrateVersioning()
		assert.NoError(t, err)

		assert.Equal(t, baseTarget, base.Proxy.TargetURL)
		assert.Equal(t, v2Target, versions[0].Proxy.TargetURL)
	})
}

func TestAPIDefinition_MigrateVersioning_StripPath(t *testing.T) {
	old := func() APIDefinition {
		return APIDefinition{
			VersionDefinition: VersionDefinition{
				StripPath: true,
				Location:  URLLocation,
			},
			VersionData: VersionData{
				NotVersioned:   false,
				DefaultVersion: v1,
				Versions: map[string]VersionInfo{
					v1: {},
					v2: {},
				},
			},
		}
	}

	check := func(t *testing.T, base APIDefinition, stripVersioningData bool) {
		t.Helper()
		versions, err := base.MigrateVersioning()
		assert.NoError(t, err)

		assert.False(t, base.VersionDefinition.StripPath)
		assert.Equal(t, stripVersioningData, base.VersionDefinition.StripVersioningData)
		assert.Len(t, versions, 1)
		assert.False(t, versions[0].VersionDefinition.StripPath)
		assert.False(t, versions[0].VersionDefinition.StripVersioningData)
	}

	t.Run("url", func(t *testing.T) {
		base := old()
		check(t, base, true)
	})

	t.Run("param", func(t *testing.T) {
		base := old()
		base.VersionDefinition.Location = URLParamLocation
		check(t, base, false)
	})

	t.Run("header", func(t *testing.T) {
		base := old()
		base.VersionDefinition.Location = HeaderLocation
		check(t, base, false)
	})
}

func TestAPIDefinition_MigrateEndpointMeta(t *testing.T) {
	const mockResponse = "mock response"
	const path = "/mock"
	const path2 = "/mock2"
	headers := map[string]string{
		"mock-header": "mock-val",
	}

	methodActions := map[string]EndpointMethodMeta{
		http.MethodGet: {
			Action:  Reply,
			Code:    http.StatusTeapot,
			Data:    mockResponse,
			Headers: headers,
		},
		http.MethodPost: {
			Action:  NoAction,
			Code:    http.StatusOK,
			Data:    "testbody",
			Headers: headers,
		},
	}

	endpointMeta := []EndPointMeta{
		{
			Path:          path,
			IgnoreCase:    true,
			MethodActions: methodActions,
		},
		{
			Disabled:      true,
			Path:          path2,
			IgnoreCase:    false,
			MethodActions: methodActions,
		},
	}

	api := APIDefinition{
		VersionData: VersionData{
			NotVersioned:   false,
			DefaultVersion: "v1",
			Versions: map[string]VersionInfo{
				"v1": {
					ExtendedPaths: ExtendedPathsSet{
						WhiteList: endpointMeta,
						BlackList: endpointMeta,
						Ignored:   endpointMeta,
					},
				},
			},
		},
	}

	_, err := api.MigrateVersioning()
	assert.NoError(t, err)

	api.MigrateEndpointMeta()

	expectedWhitelist := []EndPointMeta{
		{
			Path:       path,
			IgnoreCase: true,
			Method:     "GET",
		},
		{
			Path:       path,
			IgnoreCase: true,
			Method:     "POST",
		},
		{
			Disabled:   true,
			Path:       path2,
			IgnoreCase: false,
			Method:     "GET",
		},
		{
			Disabled:   true,
			Path:       path2,
			IgnoreCase: false,
			Method:     "POST",
		},
	}

	expectedMockResponse := []MockResponseMeta{
		{
			Disabled:   false,
			Path:       path,
			Method:     "GET",
			IgnoreCase: true,
			Code:       http.StatusTeapot,
			Body:       mockResponse,
			Headers:    headers,
		},
		{
			Disabled:   true,
			Path:       path2,
			Method:     "GET",
			IgnoreCase: false,
			Code:       http.StatusTeapot,
			Body:       mockResponse,
			Headers:    headers,
		},
	}

	assert.Equal(t, expectedWhitelist, api.VersionData.Versions[""].ExtendedPaths.WhiteList)
	assert.Equal(t, expectedWhitelist, api.VersionData.Versions[""].ExtendedPaths.BlackList)
	assert.Equal(t, expectedWhitelist, api.VersionData.Versions[""].ExtendedPaths.Ignored)
	assert.Equal(t, expectedMockResponse, api.VersionData.Versions[""].ExtendedPaths.MockResponse)
}

func TestAPIDefinition_MigrateAuthConfigNames(t *testing.T) {
	base := oldTestAPI()
	_, err := base.Migrate()
	assert.NoError(t, err)
	for k, v := range base.AuthConfigs {
		assert.Equal(t, k, v.Name)
	}
}

func TestAPIDefinition_MigrateAuthentication(t *testing.T) {
	base := oldTestAPI()
	_, err := base.Migrate()
	assert.NoError(t, err)

	assert.Len(t, base.AuthConfigs, 1)
	assert.Contains(t, base.AuthConfigs, OAuthType)
}

func TestAPIDefinition_isAuthTokenEnabled(t *testing.T) {
	api := APIDefinition{UseKeylessAccess: false}
	assert.True(t, api.isAuthTokenEnabled())

	api.EnableJWT = true
	assert.False(t, api.isAuthTokenEnabled())

	api.UseKeylessAccess = true
	api.EnableJWT = false
	api.UseStandardAuth = true
	assert.True(t, api.isAuthTokenEnabled())
}

func TestAPIDefinition_deleteAuthConfigsNotUsed(t *testing.T) {
	api := APIDefinition{
		UseKeylessAccess: true,
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

	api.deleteAuthConfigsNotUsed()
	assert.Len(t, api.AuthConfigs, 0)
}

func TestAPIDefinition_migrateCustomPluginAuth(t *testing.T) {
	testCases := []struct {
		name           string
		apiDef         APIDefinition
		expectedAPIDef APIDefinition
	}{
		{
			name:   "goplugin",
			apiDef: APIDefinition{UseGoPluginAuth: true},
			expectedAPIDef: APIDefinition{
				UseGoPluginAuth:         false,
				CustomPluginAuthEnabled: true,
			},
		},
		{
			name:   "coprocess",
			apiDef: APIDefinition{EnableCoProcessAuth: true},
			expectedAPIDef: APIDefinition{
				EnableCoProcessAuth:     false,
				CustomPluginAuthEnabled: true,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.apiDef.migrateCustomPluginAuth()
			assert.Equal(t, tc.expectedAPIDef, tc.apiDef)
		})
	}
}

func TestSetDisabledFlags(t *testing.T) {
	apiDef := APIDefinition{
		CustomMiddleware: MiddlewareSection{
			Pre:         make([]MiddlewareDefinition, 1),
			PostKeyAuth: make([]MiddlewareDefinition, 1),
			Post:        make([]MiddlewareDefinition, 1),
			Response:    make([]MiddlewareDefinition, 1),
		},
		VersionData: VersionData{
			Versions: map[string]VersionInfo{
				"": {
					ExtendedPaths: ExtendedPathsSet{
						Virtual:  make([]VirtualMeta, 2),
						GoPlugin: make([]GoPluginMeta, 1),
					},
				},
			},
		},
		EventHandlers: EventHandlerMetaConfig{
			Events: map[TykEvent][]EventHandlerTriggerConfig{
				event.QuotaExceeded: {
					{
						Handler: event.WebHookHandler,
						HandlerMeta: map[string]interface{}{
							"target_path": "https://webhook.site/uuid",
						},
					},
				},
			},
		},
	}
	expectedAPIDef := APIDefinition{
		CustomMiddleware: MiddlewareSection{
			AuthCheck: MiddlewareDefinition{
				Disabled: true,
			},
			Pre: []MiddlewareDefinition{
				{
					Disabled: true,
				},
			},
			PostKeyAuth: []MiddlewareDefinition{
				{
					Disabled: true,
				},
			},
			Post: []MiddlewareDefinition{
				{
					Disabled: true,
				},
			},
			Response: []MiddlewareDefinition{
				{
					Disabled: true,
				},
			},
			IdExtractor: MiddlewareIdExtractor{
				Disabled: true,
			},
		},
		TagsDisabled:                   true,
		UpstreamCertificatesDisabled:   true,
		CertificatePinningDisabled:     true,
		DomainDisabled:                 true,
		CustomMiddlewareBundleDisabled: true,
		ConfigDataDisabled:             true,
		Proxy: ProxyConfig{
			ServiceDiscovery: ServiceDiscoveryConfiguration{
				CacheDisabled: true,
			},
		},
		UptimeTests: UptimeTests{
			Config: UptimeTestsConfig{
				ServiceDiscovery: ServiceDiscoveryConfiguration{
					CacheDisabled: true,
				},
			},
		},
		VersionData: VersionData{
			Versions: map[string]VersionInfo{
				"": {
					ExtendedPaths: ExtendedPathsSet{
						Virtual: []VirtualMeta{
							{
								Disabled: true,
							},
							{
								Disabled: true,
							},
						},
						GoPlugin: []GoPluginMeta{
							{
								Disabled: true,
							},
						},
					},
				},
			},
		},
		GlobalRateLimit: GlobalRateLimit{
			Disabled: true,
		},
		EventHandlers: EventHandlerMetaConfig{
			Events: map[event.Event][]EventHandlerTriggerConfig{
				event.QuotaExceeded: {
					{
						Handler: event.WebHookHandler,
						HandlerMeta: map[string]interface{}{
							"target_path": "https://webhook.site/uuid",
							"disabled":    true,
						},
					},
				},
			},
		},
		DoNotTrack: true,
	}
	apiDef.SetDisabledFlags()
	assert.Equal(t, expectedAPIDef, apiDef)
	assert.EqualValues(t, expectedAPIDef.EventHandlers, apiDef.EventHandlers)
}

func TestAPIDefinition_migrateIDExtractor(t *testing.T) {
	base := oldTestAPI()
	_, err := base.Migrate()
	assert.NoError(t, err)

	assert.True(t, base.CustomMiddleware.IdExtractor.Disabled)
}

func TestAPIDefinition_migratePluginConfigData(t *testing.T) {
	base := oldTestAPI()
	_, err := base.Migrate()
	assert.NoError(t, err)

	assert.True(t, base.ConfigDataDisabled)
}

func TestAPIDefinition_migrateScopeToPolicy(t *testing.T) {
	var (
		scopeName            = "scope"
		scopeToPolicyMapping = map[string]string{"claim1": "pol1"}
	)

	expectedScopeClaim := ScopeClaim{
		ScopeClaimName: scopeName,
		ScopeToPolicy:  scopeToPolicyMapping,
	}

	check := func(t *testing.T, jwtScopeClaimName string, jwtScopeToPolicyMapping map[string]string, scopeClaim ScopeClaim) {
		t.Helper()
		assert.Equal(t, expectedScopeClaim, scopeClaim)
		assert.Empty(t, jwtScopeClaimName)
		assert.Nil(t, jwtScopeToPolicyMapping)
	}

	t.Run("jwt", func(t *testing.T) {
		apiDef := APIDefinition{
			JWTScopeClaimName:       scopeName,
			JWTScopeToPolicyMapping: scopeToPolicyMapping,
		}

		_, err := apiDef.Migrate()
		assert.NoError(t, err)
		check(t, apiDef.JWTScopeClaimName, apiDef.JWTScopeToPolicyMapping, apiDef.Scopes.JWT)
	})

	t.Run("oidc", func(t *testing.T) {
		apiDef := APIDefinition{
			UseOpenID:               true,
			JWTScopeClaimName:       scopeName,
			JWTScopeToPolicyMapping: scopeToPolicyMapping,
		}

		_, err := apiDef.Migrate()
		assert.NoError(t, err)
		check(t, apiDef.JWTScopeClaimName, apiDef.JWTScopeToPolicyMapping, apiDef.Scopes.OIDC)
	})

}

func TestAPIDefinition_migrateResponseProcessors(t *testing.T) {
	base := oldTestAPI()
	_, err := base.Migrate()
	assert.NoError(t, err)

	assert.Empty(t, base.ResponseProcessors)
}

func TestAPIDefinition_migrateGlobalRateLimit(t *testing.T) {
	t.Run("per=0,rate=0", func(t *testing.T) {
		base := oldTestAPI()
		_, err := base.Migrate()
		assert.NoError(t, err)

		assert.True(t, base.GlobalRateLimit.Disabled)
	})

	t.Run("per!=0,rate=0", func(t *testing.T) {
		base := oldTestAPI()
		base.GlobalRateLimit.Per = 120
		_, err := base.Migrate()
		assert.NoError(t, err)

		assert.True(t, base.GlobalRateLimit.Disabled)
	})

	t.Run("per=0,rate!=0", func(t *testing.T) {
		base := oldTestAPI()
		base.GlobalRateLimit.Rate = 1
		_, err := base.Migrate()
		assert.NoError(t, err)

		assert.True(t, base.GlobalRateLimit.Disabled)
	})

	t.Run("per!=0,rate!=0", func(t *testing.T) {
		base := oldTestAPI()
		base.GlobalRateLimit.Rate = 1
		base.GlobalRateLimit.Per = 1
		_, err := base.Migrate()
		assert.NoError(t, err)

		assert.False(t, base.GlobalRateLimit.Disabled)
	})
}

func TestAPIDefinition_migrateIPAccessControl(t *testing.T) {
	t.Run("whitelisting", func(t *testing.T) {
		t.Run("EnableIpWhitelisting=true, no whitelist", func(t *testing.T) {
			base := oldTestAPI()
			base.EnableIpWhiteListing = true
			_, err := base.Migrate()
			assert.NoError(t, err)
			assert.True(t, base.IPAccessControlDisabled)
		})

		t.Run("IPWhiteListEnabled=true, non-empty whitelist", func(t *testing.T) {
			base := oldTestAPI()
			base.EnableIpWhiteListing = true
			base.AllowedIPs = []string{"127.0.0.1"}
			_, err := base.Migrate()
			assert.NoError(t, err)
			assert.False(t, base.IPAccessControlDisabled)
		})

		t.Run("EnableIpWhitelisting=false, no whitelist", func(t *testing.T) {
			base := oldTestAPI()
			base.EnableIpWhiteListing = false
			_, err := base.Migrate()
			assert.NoError(t, err)
			assert.True(t, base.IPAccessControlDisabled)
		})

		t.Run("IPWhiteListEnabled=false, non-empty whitelist", func(t *testing.T) {
			base := oldTestAPI()
			base.EnableIpWhiteListing = false
			base.AllowedIPs = []string{"127.0.0.1"}
			_, err := base.Migrate()
			assert.NoError(t, err)
			assert.True(t, base.IPAccessControlDisabled)
		})
	})

	t.Run("blacklisting", func(t *testing.T) {
		t.Run("EnableIpBlacklisting=true, no blacklist", func(t *testing.T) {
			base := oldTestAPI()
			base.EnableIpBlacklisting = true
			_, err := base.Migrate()
			assert.NoError(t, err)
			assert.True(t, base.IPAccessControlDisabled)
		})

		t.Run("EnableIpBlacklisting=true, non-empty blacklist", func(t *testing.T) {
			base := oldTestAPI()
			base.EnableIpBlacklisting = true
			base.BlacklistedIPs = []string{"127.0.0.1"}
			_, err := base.Migrate()
			assert.NoError(t, err)
			assert.False(t, base.IPAccessControlDisabled)
		})

		t.Run("EnableIpBlacklisting=false, no blacklist", func(t *testing.T) {
			base := oldTestAPI()
			base.EnableIpBlacklisting = false
			_, err := base.Migrate()
			assert.NoError(t, err)
			assert.True(t, base.IPAccessControlDisabled)
		})

		t.Run("IPWhiteListEnabled=false, non-empty blacklist", func(t *testing.T) {
			base := oldTestAPI()
			base.EnableIpBlacklisting = false
			base.BlacklistedIPs = []string{"127.0.0.1"}
			_, err := base.Migrate()
			assert.NoError(t, err)
			assert.True(t, base.IPAccessControlDisabled)
		})
	})

}

func TestMigrateCachePlugin(t *testing.T) {
	tests := []struct {
		name string
		api  *APIDefinition
		want *APIDefinition
	}{
		{
			name: "empty cache config - no migration needed",
			api: &APIDefinition{
				VersionData: VersionData{
					Versions: map[string]VersionInfo{
						"": {
							UseExtendedPaths: false,
							ExtendedPaths: ExtendedPathsSet{
								Cached: nil,
							},
						},
					},
				},
			},
			want: &APIDefinition{
				VersionData: VersionData{
					Versions: map[string]VersionInfo{
						"": {
							UseExtendedPaths: false,
							ExtendedPaths: ExtendedPathsSet{
								Cached: nil,
							},
						},
					},
				},
			},
		},
		{
			name: "migrate simple cache paths to advanced config",
			api: &APIDefinition{
				CacheOptions: CacheOptions{
					EnableCache:            true,
					CacheTimeout:           120,
					CacheOnlyResponseCodes: []int{200, 404},
				},
				VersionData: VersionData{
					Versions: map[string]VersionInfo{
						"": {
							UseExtendedPaths: true,
							ExtendedPaths: ExtendedPathsSet{
								Cached: []string{"/test", "/api"},
							},
						},
					},
				},
			},
			want: &APIDefinition{
				CacheOptions: CacheOptions{
					EnableCache:            true,
					CacheTimeout:           120,
					CacheOnlyResponseCodes: []int{200, 404},
				},
				VersionData: VersionData{
					Versions: map[string]VersionInfo{
						"": {
							UseExtendedPaths: true,
							ExtendedPaths: ExtendedPathsSet{
								Cached: nil,
								AdvanceCacheConfig: []CacheMeta{
									{
										Path:                   "/test",
										Method:                 http.MethodGet,
										Disabled:               false,
										Timeout:                120,
										CacheOnlyResponseCodes: []int{200, 404},
									},
									{
										Path:                   "/test",
										Method:                 http.MethodHead,
										Disabled:               false,
										Timeout:                120,
										CacheOnlyResponseCodes: []int{200, 404},
									},
									{
										Path:                   "/test",
										Method:                 http.MethodOptions,
										Disabled:               false,
										Timeout:                120,
										CacheOnlyResponseCodes: []int{200, 404},
									},
									{
										Path:                   "/api",
										Method:                 http.MethodGet,
										Disabled:               false,
										Timeout:                120,
										CacheOnlyResponseCodes: []int{200, 404},
									},
									{
										Path:                   "/api",
										Method:                 http.MethodHead,
										Disabled:               false,
										Timeout:                120,
										CacheOnlyResponseCodes: []int{200, 404},
									},
									{
										Path:                   "/api",
										Method:                 http.MethodOptions,
										Disabled:               false,
										Timeout:                120,
										CacheOnlyResponseCodes: []int{200, 404},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "preserve existing advanced cache config",
			api: &APIDefinition{
				CacheOptions: CacheOptions{
					EnableCache:            true,
					CacheTimeout:           120,
					CacheOnlyResponseCodes: []int{200},
				},
				VersionData: VersionData{
					Versions: map[string]VersionInfo{
						"": {
							UseExtendedPaths: true,
							ExtendedPaths: ExtendedPathsSet{
								Cached: []string{"/test"},
								AdvanceCacheConfig: []CacheMeta{
									{
										Path:                   "/existing",
										Method:                 http.MethodPost,
										Disabled:               false,
										Timeout:                60,
										CacheOnlyResponseCodes: []int{201},
									},
								},
							},
						},
					},
				},
			},
			want: &APIDefinition{
				CacheOptions: CacheOptions{
					EnableCache:            true,
					CacheTimeout:           120,
					CacheOnlyResponseCodes: []int{200},
				},
				VersionData: VersionData{
					Versions: map[string]VersionInfo{
						"": {
							UseExtendedPaths: true,
							ExtendedPaths: ExtendedPathsSet{
								Cached: nil,
								AdvanceCacheConfig: []CacheMeta{
									{
										Path:                   "/test",
										Method:                 http.MethodGet,
										Disabled:               false,
										Timeout:                120,
										CacheOnlyResponseCodes: []int{200},
									},
									{
										Path:                   "/test",
										Method:                 http.MethodHead,
										Disabled:               false,
										Timeout:                120,
										CacheOnlyResponseCodes: []int{200},
									},
									{
										Path:                   "/test",
										Method:                 http.MethodOptions,
										Disabled:               false,
										Timeout:                120,
										CacheOnlyResponseCodes: []int{200},
									},
									{
										Path:                   "/existing",
										Method:                 http.MethodPost,
										Disabled:               false,
										Timeout:                60,
										CacheOnlyResponseCodes: []int{201},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.api.MigrateCachePlugin()
			if !reflect.DeepEqual(tt.api, tt.want) {
				t.Errorf("MigrateCachePlugin() = %v, want %v", tt.api, tt.want)
			}
		})
	}
}

func TestCreateAdvancedCacheConfig(t *testing.T) {
	tests := []struct {
		name      string
		cacheOpts CacheOptions
		path      string
		method    string
		want      CacheMeta
	}{
		{
			name: "default settings with cache enabled",
			cacheOpts: CacheOptions{
				EnableCache: true,
			},
			path:   "/test",
			method: "GET",
			want: CacheMeta{
				Disabled: false,
				Path:     "/test",
				Method:   "GET",
				Timeout:  DefaultCacheTimeout,
			},
		},
		{
			name: "custom timeout with cache enabled",
			cacheOpts: CacheOptions{
				EnableCache:  true,
				CacheTimeout: 120,
			},
			path:   "/custom",
			method: "POST",
			want: CacheMeta{
				Disabled: false,
				Path:     "/custom",
				Method:   "POST",
				Timeout:  120,
			},
		},
		{
			name: "cache disabled",
			cacheOpts: CacheOptions{
				EnableCache:  false,
				CacheTimeout: 30,
			},
			path:   "/disabled",
			method: "GET",
			want: CacheMeta{
				Disabled: true,
				Path:     "/disabled",
				Method:   "GET",
				Timeout:  30,
			},
		},
		{
			name: "with response codes",
			cacheOpts: CacheOptions{
				EnableCache:            true,
				CacheOnlyResponseCodes: []int{200, 201},
			},
			path:   "/with-codes",
			method: "GET",
			want: CacheMeta{
				Disabled:               false,
				Path:                   "/with-codes",
				Method:                 "GET",
				Timeout:                DefaultCacheTimeout,
				CacheOnlyResponseCodes: []int{200, 201},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createAdvancedCacheConfig(tt.cacheOpts, tt.path, tt.method)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createAdvancedCacheConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
