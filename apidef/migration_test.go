package apidef

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
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
}

var testV2ExtendedPaths = ExtendedPathsSet{
	WhiteList: []EndPointMeta{
		{Method: http.MethodGet, Path: "/get2"},
	},
}

func oldTestAPI() APIDefinition {
	return APIDefinition{
		Id:     dbID,
		APIID:  apiID,
		Name:   baseAPIName,
		Active: true,
		Proxy:  ProxyConfig{TargetURL: baseTarget, ListenPath: listenPath},
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
			"authToken": {
				AuthHeaderName: "Authorization",
				UseParam:       true,
				ParamName:      "Authorization",
				UseCookie:      true,
				CookieName:     "Authorization",
			},
			"jwt": {
				AuthHeaderName: "Authorization",
				UseParam:       true,
				ParamName:      "Authorization",
				UseCookie:      true,
				CookieName:     "Authorization",
			},
			"oidc": {
				AuthHeaderName: "Authorization",
				UseParam:       true,
				ParamName:      "Authorization",
				UseCookie:      true,
				CookieName:     "Authorization",
			},
			"hmac": {
				AuthHeaderName: "Authorization",
				UseParam:       true,
				ParamName:      "Authorization",
				UseCookie:      true,
				CookieName:     "Authorization",
			},
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
	expectedVersion.Internal = true
	expectedVersion.Expiration = exp2
	expectedVersion.Proxy.ListenPath += "-" + v2 + "/"
	expectedVersion.VersionDefinition = VersionDefinition{}
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

		expectedBaseDefinition := VersionDefinition{
			Location:            URLLocation,
			Key:                 key,
			StripVersioningData: true,
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

func TestAPIDefinition_MigrateCachePlugin(t *testing.T) {
	versionInfo := VersionInfo{
		UseExtendedPaths: true,
		ExtendedPaths: ExtendedPathsSet{
			Cached: []string{"test"},
		},
	}

	old := APIDefinition{
		VersionData: VersionData{
			Versions: map[string]VersionInfo{
				"": versionInfo,
			},
		},
	}

	old.MigrateCachePlugin()

	cacheItemGet := CacheMeta{
		Method:        http.MethodGet,
		Disabled:      false,
		Path:          "test",
		CacheKeyRegex: "",
	}
	cacheItemHead := cacheItemGet
	cacheItemHead.Method = http.MethodHead

	cacheItemOptions := cacheItemGet
	cacheItemOptions.Method = http.MethodOptions
	expectedAdvCacheMethods := []CacheMeta{
		cacheItemGet,
		cacheItemHead,
		cacheItemOptions,
	}

	assert.Empty(t, old.VersionData.Versions[""].ExtendedPaths.Cached)
	assert.Equal(t, expectedAdvCacheMethods, old.VersionData.Versions[""].ExtendedPaths.AdvanceCacheConfig)
}

func TestAPIDefinition_MigrateAuthConfigNames(t *testing.T) {
	base := oldTestAPI()
	_, err := base.Migrate()
	assert.NoError(t, err)
	for k, v := range base.AuthConfigs {
		assert.Equal(t, k, v.Name)
	}
}
