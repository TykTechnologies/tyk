package apidef

import (
	"errors"
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

	if !a.VersionData.NotVersioned {
		if _, ok := a.VersionData.Versions[a.VersionData.DefaultVersion]; !ok {
			return nil, errors.New("not migratable - if versioned, default version should match one of the versions")
		}

		for vName, vInfo := range a.VersionData.Versions {
			if a.VersionData.DefaultVersion == vName {
				continue
			}

			newAPI := *a

			newID := uuid.NewV4()
			apiID := strings.Replace(newID.String(), "-", "", -1)

			newAPI.APIID = apiID
			newAPI.Id = ""
			newAPI.Name += "-" + url.QueryEscape(vName)
			newAPI.Internal = true
			newAPI.VersionDefinition = VersionDefinition{}
			newAPI.VersionData.NotVersioned = true
			newAPI.VersionData.DefaultVersion = ""

			if vInfo.OverrideTarget != "" {
				newAPI.Proxy.TargetURL = vInfo.OverrideTarget
				vInfo.OverrideTarget = ""
			}

			newAPI.Proxy.ListenPath = strings.TrimSuffix(newAPI.Proxy.ListenPath, "/") + "-" + url.QueryEscape(vName) + "/"

			newAPI.Expiration = vInfo.Expires
			vInfo.Expires = ""

			newAPI.VersionData.Versions = map[string]VersionInfo{
				"": vInfo,
			}

			versions = append(versions, newAPI)
			delete(a.VersionData.Versions, vName)

			if a.VersionDefinition.Versions == nil {
				a.VersionDefinition.Versions = make(map[string]string)
			}

			a.VersionDefinition.Versions[vName] = newAPI.APIID
		}
	}

	a.VersionDefinition.Enabled = !a.VersionData.NotVersioned
	if a.VersionDefinition.Enabled {
		a.VersionDefinition.Default = Self
		a.VersionDefinition.Name = a.VersionData.DefaultVersion
	}

	if a.VersionDefinition.Location == URLLocation {
		a.VersionDefinition.StripVersioningData = a.VersionDefinition.StripPath
	}

	a.VersionDefinition.StripPath = false

	defaultVersionInfo := a.VersionData.Versions[a.VersionData.DefaultVersion]
	if a.VersionData.NotVersioned {
		for _, v := range a.VersionData.Versions {
			defaultVersionInfo = v
			a.VersionData.Versions = map[string]VersionInfo{}
			break
		}
	}

	if defaultVersionInfo.OverrideTarget != "" {
		a.Proxy.TargetURL = defaultVersionInfo.OverrideTarget
		defaultVersionInfo.OverrideTarget = ""
	}

	if !a.VersionData.NotVersioned {
		a.Expiration = defaultVersionInfo.Expires
	}

	defaultVersionInfo.Expires = ""

	a.VersionData.Versions[""] = defaultVersionInfo
	delete(a.VersionData.Versions, a.VersionData.DefaultVersion)

	a.VersionData.DefaultVersion = ""
	a.VersionData.NotVersioned = true

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
	for i := 0; i < len(versions); i++ {
		versions[i].MigrateEndpointMeta()
	}

	return versions, nil
}

func (a *APIDefinition) MigrateCachePlugin() (err error) {
	if a.VersionDefinition.Enabled || len(a.VersionDefinition.Versions) != 0 {
		return errors.New("not migratable - new versioning is enabled")
	}

	if a.VersionData.NotVersioned && len(a.VersionData.Versions) > 1 {
		return errors.New("not migratable - if not versioned, there should be 1 version info in versions map")
	}

	for vName, vInfo := range a.VersionData.Versions {
		var updated = false
		if vInfo.UseExtendedPaths && len(vInfo.ExtendedPaths.Cached) > 0 {
			var methods = []CacheMeta{}
			for _, cache := range vInfo.ExtendedPaths.Cached {
				newCache := CacheMeta{
					Path:     cache,
					Disabled: false,
				}
				methods = append(methods, newCache)
			}
			vInfo.ExtendedPaths.AdvanceCacheConfig = methods
			updated = true
		}

		if updated {
			delete(a.VersionData.Versions, vName)
			a.VersionData.Versions[vName] = vInfo
		}

	}

	return
}
