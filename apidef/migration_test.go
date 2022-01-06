package apidef

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPIDefinition_MigrateVersioning(t *testing.T) {
	const (
		dbID       = "apiID"
		apiID      = "apiID"
		listenPath = "listenPath"
		baseTarget = "base.com"
		v1Target   = "v1.com"
		v2Target   = "v2.com"
		v1         = "v1"
		v2         = "v2"
		exp1       = "exp1"
		exp2       = "exp2"
	)

	old := func() APIDefinition {
		return APIDefinition{
			Id:     dbID,
			APIID:  apiID,
			Active: true,
			Proxy:  ProxyConfig{TargetURL: baseTarget, ListenPath: listenPath},
			VersionDefinition: VersionDefinition{
				Location:  "url",
				Key:       "version",
				StripPath: true,
			},
			VersionData: VersionData{
				NotVersioned:   false,
				DefaultVersion: v1,
				Versions: map[string]VersionInfo{
					v1: {
						Expires: exp1,
					},
					v2: {
						Expires: exp2,
					},
				},
			},
		}
	}

	base := old()
	versions, err := base.MigrateVersioning()
	assert.NoError(t, err)

	expectedBase := base
	expectedBase.Expiration = exp1
	expectedBase.VersionData.NotVersioned = true
	expectedBase.VersionData.DefaultVersion = ""
	expectedBase.VersionData.Versions = map[string]VersionInfo{
		"": {
			Name:           "",
			Expires:        "",
			OverrideTarget: "",
		},
	}

	expectedBase.VersionDefinition.Enabled = true
	expectedBase.VersionDefinition.Name = v1
	expectedBase.VersionDefinition.Default = Self
	expectedBase.VersionDefinition.Versions = map[string]string{
		v2: versions[0].APIID,
	}

	assert.Equal(t, expectedBase, base)

	expectedVersion := old()
	expectedVersion.Id = ""
	expectedVersion.APIID = ""
	expectedVersion.Name += "-" + v2
	expectedVersion.Internal = true
	expectedVersion.Expiration = exp2
	expectedVersion.Proxy.ListenPath += "-" + v2 + "/"
	expectedVersion.VersionDefinition = VersionDefinition{}
	expectedVersion.VersionData.NotVersioned = true
	expectedVersion.VersionData.DefaultVersion = ""
	expectedVersion.VersionData.Versions = map[string]VersionInfo{
		"": {},
	}

	assert.Len(t, versions, 1)
	expectedVersion.APIID = versions[0].APIID
	assert.Equal(t, expectedVersion, versions[0])

	t.Run("override target", func(t *testing.T) {
		t.Run("base", func(t *testing.T) {
			overrideTargetBase := old()
			vInfo := overrideTargetBase.VersionData.Versions[v1]
			vInfo.OverrideTarget = v1Target
			overrideTargetBase.VersionData.Versions[v1] = vInfo

			versions, err = overrideTargetBase.MigrateVersioning()
			assert.NoError(t, err)

			expectedBase.Proxy.TargetURL = v1Target

			expectedBase.VersionDefinition.Versions[v2] = versions[0].APIID
			assert.Equal(t, expectedBase, overrideTargetBase)

			assert.Len(t, versions, 1)
			expectedVersion.APIID = versions[0].APIID
			assert.Equal(t, expectedVersion, versions[0])
		})

		t.Run("version", func(t *testing.T) {
			overrideTargetBase := old()
			vInfo := overrideTargetBase.VersionData.Versions[v2]
			vInfo.OverrideTarget = v2Target
			overrideTargetBase.VersionData.Versions[v2] = vInfo

			versions, err = overrideTargetBase.MigrateVersioning()
			assert.NoError(t, err)

			expectedBase.Proxy.TargetURL = baseTarget
			expectedBase.VersionDefinition.Versions[v2] = versions[0].APIID

			assert.Equal(t, expectedBase, overrideTargetBase)

			expectedVersion.Proxy.TargetURL = v2Target
			assert.Len(t, versions, 1)
			expectedVersion.APIID = versions[0].APIID
			assert.Equal(t, expectedVersion, versions[0])
		})
	})

	t.Run("version disabled", func(t *testing.T) {
		versionDisabledBase := old()
		versionDisabledBase.VersionData.NotVersioned = true

		t.Run("multiple versions", func(t *testing.T) {
			versions, err = versionDisabledBase.MigrateVersioning()
			assert.EqualError(t, err, "not migratable - if not versioned, there should be just one version info in versions map")
		})

		delete(versionDisabledBase.VersionData.Versions, v2)

		t.Run("one version", func(t *testing.T) {
			versions, err = versionDisabledBase.MigrateVersioning()
			assert.NoError(t, err)
			assert.Nil(t, versions)

			expectedBase.Expiration = ""
			expectedBase.VersionDefinition.Enabled = false
			expectedBase.VersionDefinition.Name = ""
			expectedBase.VersionDefinition.Default = ""
			expectedBase.VersionDefinition.Versions = nil

			assert.Len(t, expectedBase.VersionData.Versions, 1)
			assert.Contains(t, expectedBase.VersionData.Versions, "")

			assert.Equal(t, expectedBase, versionDisabledBase)
		})
	})
}

func TestAPIDefinition_MigrateVersioning_StripPath(t *testing.T) {
	const (
		v1 = "v1"
		v2 = "v2"
	)

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
