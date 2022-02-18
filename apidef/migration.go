package apidef

import (
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"

	uuid "github.com/satori/go.uuid"
)

func (a *APIDefinition) MigrateVersioning() (versions []APIDefinition, err error) {
	if a.VersionDefinition.Enabled || len(a.VersionDefinition.Versions) != 0 {
		return nil, errors.New("not migratable - new versioning is enabled")
	}

	if a.VersionData.NotVersioned && len(a.VersionData.Versions) > 1 {
		return nil, errors.New("not migratable - if not versioned, there should be just one version info in versions map")
	}

	a.VersionDefinition.Enabled = !a.VersionData.NotVersioned
	if a.VersionDefinition.Enabled {
		a.VersionDefinition.Default = Self
	}

	base := a.VersionData.DefaultVersion
	var baseVInfo VersionInfo
	var found bool
	if baseVInfo, found = a.VersionData.Versions[base]; !found {
		a.VersionDefinition.Default = ""
		base = "Default"
		if baseVInfo, found = a.VersionData.Versions[base]; !found {
			var sortedVersionNames []string
			for vName := range a.VersionData.Versions {
				sortedVersionNames = append(sortedVersionNames, vName)
			}

			sort.Strings(sortedVersionNames)
			if len(sortedVersionNames) > 0 {
				base = sortedVersionNames[0]
			}

			baseVInfo = a.VersionData.Versions[base]
		}
	}

	delete(a.VersionData.Versions, base)

	if a.VersionDefinition.Enabled {
		a.VersionDefinition.Name = base

		for vName, vInfo := range a.VersionData.Versions {
			newAPI := *a

			newID := uuid.NewV4()
			apiID := strings.Replace(newID.String(), "-", "", -1)

			newAPI.APIID = apiID
			newAPI.Id = ""
			newAPI.Name += "-" + url.QueryEscape(vName)
			newAPI.Internal = true
			newAPI.Proxy.ListenPath = strings.TrimSuffix(newAPI.Proxy.ListenPath, "/") + "-" + url.QueryEscape(vName) + "/"
			newAPI.VersionDefinition = VersionDefinition{}

			// Version API Expires migration
			newAPI.Expiration = vInfo.Expires
			vInfo.Expires = ""

			// Version API OverrideTarget migration
			if vInfo.OverrideTarget != "" {
				newAPI.Proxy.TargetURL = vInfo.OverrideTarget
				vInfo.OverrideTarget = ""
			}

			newAPI.VersionData = VersionData{
				NotVersioned: true,
				Versions: map[string]VersionInfo{
					"": vInfo,
				},
			}

			if a.VersionDefinition.Versions == nil {
				a.VersionDefinition.Versions = make(map[string]string)
			}

			a.VersionDefinition.Versions[vName] = newAPI.APIID

			versions = append(versions, newAPI)
		}
	}

	// Base API StripPath migration
	if a.VersionDefinition.Location == URLLocation {
		a.VersionDefinition.StripVersioningData = a.VersionDefinition.StripPath
	}

	a.VersionDefinition.StripPath = false

	// Base API Expires migration
	if a.VersionDefinition.Enabled {
		a.Expiration = baseVInfo.Expires
	}

	baseVInfo.Expires = ""

	// Base API OverrideTarget migration
	if baseVInfo.OverrideTarget != "" {
		a.Proxy.TargetURL = baseVInfo.OverrideTarget
		baseVInfo.OverrideTarget = ""
	}

	a.VersionData = VersionData{
		NotVersioned: true,
		Versions: map[string]VersionInfo{
			"": baseVInfo,
		},
	}

	return
}

const (
	typeWhitelist = 0
	typeBlacklist = 1
	typeIgnore    = 2
)

func (a *APIDefinition) MigrateEndpointMeta() {
	a.migrateEndpointMetaByType(typeIgnore)
	a.migrateEndpointMetaByType(typeBlacklist)
	a.migrateEndpointMetaByType(typeWhitelist)
}

func (a *APIDefinition) migrateEndpointMetaByType(typ int) {
	vInfo := a.VersionData.Versions[""]

	list := vInfo.ExtendedPaths.WhiteList
	if typ == typeBlacklist {
		list = vInfo.ExtendedPaths.BlackList
	} else if typ == typeIgnore {
		list = vInfo.ExtendedPaths.Ignored
	}

	var resList []EndPointMeta
	var resMockResponse []MockResponseMeta
	for _, meta := range list {
		var tempList []EndPointMeta
		var tempMockResponse []MockResponseMeta
		for method, action := range meta.MethodActions {
			newMeta := meta
			newMeta.Method = method

			newMeta.MethodActions = nil
			tempList = append(tempList, newMeta)

			if action.Action == NoAction {
				continue
			}

			mockMeta := MockResponseMeta{Path: meta.Path, IgnoreCase: meta.IgnoreCase}
			mockMeta.Disabled = meta.Disabled || (!meta.Disabled && action.Action != Reply)
			mockMeta.Method = method
			mockMeta.Code = action.Code
			mockMeta.Body = action.Data
			mockMeta.Headers = action.Headers

			tempMockResponse = append(tempMockResponse, mockMeta)
		}

		sort.Slice(tempList, func(i, j int) bool {
			return tempList[i].Method < tempList[j].Method
		})

		resList = append(resList, tempList...)

		sort.Slice(tempMockResponse, func(i, j int) bool {
			return tempMockResponse[i].Method < tempMockResponse[j].Method
		})

		resMockResponse = append(resMockResponse, tempMockResponse...)
	}

	if typ == typeBlacklist {
		vInfo.ExtendedPaths.BlackList = resList
	} else if typ == typeIgnore {
		vInfo.ExtendedPaths.Ignored = resList
	} else {
		vInfo.ExtendedPaths.WhiteList = resList
	}

	for _, search := range resMockResponse {
		contains := false
		for _, mock := range vInfo.ExtendedPaths.MockResponse {
			if mock.Path == search.Path && mock.Method == search.Method {
				contains = true
				break
			}
		}

		if !contains {
			vInfo.ExtendedPaths.MockResponse = append(vInfo.ExtendedPaths.MockResponse, search)
		}
	}

	a.VersionData.Versions[""] = vInfo
}

func (a *APIDefinition) Migrate() (versions []APIDefinition, err error) {
	versions, err = a.MigrateVersioning()
	if err != nil {
		return nil, err
	}

	a.MigrateEndpointMeta()
	a.MigrateCachePlugin()

	for k, v := range a.AuthConfigs {
		v.Name = k
		a.AuthConfigs[k] = v
	}

	for i := 0; i < len(versions); i++ {
		versions[i].MigrateEndpointMeta()
		a.MigrateCachePlugin()
	}

	return versions, nil
}

func (a *APIDefinition) MigrateCachePlugin() {
	vInfo := a.VersionData.Versions[""]
	list := vInfo.ExtendedPaths.Cached

	if vInfo.UseExtendedPaths && len(list) > 0 {
		var advCacheMethods []CacheMeta
		for _, cache := range list {
			newGetMethodCache := CacheMeta{
				Path:   cache,
				Method: http.MethodGet,
			}
			newHeadMethodCache := CacheMeta{
				Path:   cache,
				Method: http.MethodHead,
			}
			newOptionsMethodCache := CacheMeta{
				Path:   cache,
				Method: http.MethodOptions,
			}
			advCacheMethods = append(advCacheMethods, newGetMethodCache, newHeadMethodCache, newOptionsMethodCache)
		}

		vInfo.ExtendedPaths.AdvanceCacheConfig = advCacheMethods
		// reset cache to empty
		vInfo.ExtendedPaths.Cached = nil
	}

	a.VersionData.Versions[""] = vInfo
}
