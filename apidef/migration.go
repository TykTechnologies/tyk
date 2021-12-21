package apidef

import (
	"errors"
	"net/url"
	"strings"
)

func (a *APIDefinition) MigrateVersioning() (versions []APIDefinition, err error) {
	if a.VersionDefinition.Enabled || len(a.VersionDefinition.Versions) != 0 {
		return nil, errors.New("not migratable - new versioning is enabled")
	}

	if a.VersionData.NotVersioned && len(a.VersionData.Versions) > 1 {
		return nil, errors.New("not migratable - if not versioned, there should be 1 version info in versions map")
	}

	for vName, vInfo := range a.VersionData.Versions {
		if a.VersionData.DefaultVersion == vName {
			continue
		}

		newAPI := *a
		newAPI.APIID = ""
		newAPI.Id = ""
		newAPI.VersionDefinition = VersionDefinition{}
		newAPI.VersionData.NotVersioned = true
		newAPI.VersionData.DefaultVersion = ""

		if vInfo.OverrideTarget != "" {
			newAPI.Proxy.ListenPath = vInfo.OverrideTarget
		} else { // listen path of each version should be unique
			newAPI.Proxy.ListenPath = strings.TrimSuffix(newAPI.Proxy.ListenPath, "/") + "-" + url.QueryEscape(vName) + "/"
		}

		newAPI.Expiration = vInfo.Expires

		versions = append(versions, newAPI)
		delete(a.VersionData.Versions, vName)

		if a.VersionDefinition.Versions == nil {
			a.VersionDefinition.Versions = make(map[string]string)
		}

		a.VersionDefinition.Versions[vName] = ""
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

	if defaultVersionInfo.OverrideTarget != "" {
		a.Proxy.ListenPath = defaultVersionInfo.OverrideTarget
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
