package apidef

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPIDefinition_MigrateVersioning(t *testing.T) {
	const (
		dbID       = "apiID"
		apiID      = "apiID"
		listenPath = "listenPath"
		v1Target   = "v1.com"
		v2Target   = "v2.com"
		v1         = "v1"
		v2         = "v2"
	)

	old := func() APIDefinition {
		return APIDefinition{
			Id:     dbID,
			APIID:  apiID,
			Active: true,
			Proxy:  ProxyConfig{ListenPath: listenPath},
			VersionDefinition: VersionDefinition{
				Location:  "url",
				Key:       "version",
				StripPath: true,
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

	base := old()
	versions, err := base.MigrateVersioning()
	assert.NoError(t, err)

	expectedBase := base
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
		v2: "",
	}

	assert.Equal(t, expectedBase, base)

	expectedVersion := old()
	expectedVersion.Id = ""
	expectedVersion.APIID = ""
	expectedVersion.Proxy.ListenPath += "-" + v2 + "/"
	expectedVersion.VersionDefinition = VersionDefinition{}
	expectedVersion.VersionData.NotVersioned = true
	expectedVersion.VersionData.DefaultVersion = ""
	expectedVersion.VersionData.Versions = map[string]VersionInfo{
		"": {},
	}

	assert.Len(t, versions, 1)
	assert.Equal(t, expectedVersion, versions[0])

	t.Run("override target", func(t *testing.T) {
		t.Run("base", func(t *testing.T) {
			overrideTargetBase := old()
			vInfo := overrideTargetBase.VersionData.Versions[v1]
			vInfo.OverrideTarget = v1Target
			overrideTargetBase.VersionData.Versions[v1] = vInfo

			versions, err = overrideTargetBase.MigrateVersioning()
			assert.NoError(t, err)

			expectedBase.Proxy.ListenPath = v1Target

			assert.Equal(t, expectedBase, overrideTargetBase)

			assert.Len(t, versions, 1)
			assert.Equal(t, expectedVersion, versions[0])
		})

		t.Run("version", func(t *testing.T) {
			overrideTargetBase := old()
			vInfo := overrideTargetBase.VersionData.Versions[v2]
			vInfo.OverrideTarget = v2Target
			overrideTargetBase.VersionData.Versions[v2] = vInfo

			versions, err = overrideTargetBase.MigrateVersioning()
			assert.NoError(t, err)

			expectedBase.Proxy.ListenPath = listenPath

			assert.Equal(t, expectedBase, overrideTargetBase)

			expectedVersion.Proxy.ListenPath = v2Target
			assert.Len(t, versions, 1)
			assert.Equal(t, expectedVersion, versions[0])
		})
	})

	t.Run("version disabled", func(t *testing.T) {
		versionDisabledBase := old()
		versionDisabledBase.VersionData.NotVersioned = true

		t.Run("multiple versions", func(t *testing.T) {
			versions, err = versionDisabledBase.MigrateVersioning()
			assert.EqualError(t, err, "not migratable - if not versioned, there should be 1 version info in versions map")
		})

		delete(versionDisabledBase.VersionData.Versions, v2)

		t.Run("one version", func(t *testing.T) {
			versions, err = versionDisabledBase.MigrateVersioning()
			assert.NoError(t, err)
			assert.Nil(t, versions)

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
