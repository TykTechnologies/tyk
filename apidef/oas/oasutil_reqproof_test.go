package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

type reqproofOASUtilTarget struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Count   int    `json:"count"`
}

type reqproofOASUtilOmitShape struct {
	Flag   bool
	Items  []string
	Labels map[string]string
	Nested *reqproofOASUtilNestedShape
}

type reqproofOASUtilNestedShape struct {
	Labels map[string]string
}

// Verifies: SYS-REQ-104, SW-REQ-055
// SW-REQ-055:nominal:nominal
// SW-REQ-055:boundary:nominal
// SW-REQ-055:determinism:nominal
func TestOASUtilityHelpersPreserveSupportShapes(t *testing.T) {
	t.Run("map input populates target struct and non-map input is rejected", func(t *testing.T) {
		target := reqproofOASUtilTarget{}

		converted := toStructIfMap(map[string]interface{}{
			"name":    "primary",
			"enabled": true,
			"count":   float64(3),
		}, &target)

		require.True(t, converted)
		assert.Equal(t, reqproofOASUtilTarget{Name: "primary", Enabled: true, Count: 3}, target)

		target = reqproofOASUtilTarget{Name: "unchanged", Enabled: true, Count: 7}
		converted = toStructIfMap(reqproofOASUtilTarget{Name: "direct"}, &target)

		require.False(t, converted)
		assert.Equal(t, reqproofOASUtilTarget{Name: "unchanged", Enabled: true, Count: 7}, target)
	})

	t.Run("omit alias classifies empty and populated shapes consistently", func(t *testing.T) {
		assert.True(t, ShouldOmit(reqproofOASUtilOmitShape{}))
		assert.True(t, ShouldOmit(reqproofOASUtilOmitShape{
			Items:  []string{},
			Labels: map[string]string{},
			Nested: &reqproofOASUtilNestedShape{Labels: map[string]string{}},
		}))

		assert.False(t, ShouldOmit(reqproofOASUtilOmitShape{Flag: true}))
		assert.False(t, ShouldOmit(reqproofOASUtilOmitShape{Items: []string{"x"}}))
		assert.False(t, ShouldOmit(reqproofOASUtilOmitShape{Labels: map[string]string{"k": "v"}}))
		assert.False(t, ShouldOmit(reqproofOASUtilOmitShape{Nested: &reqproofOASUtilNestedShape{Labels: map[string]string{"k": "v"}}}))
	})

	t.Run("main version helpers initialize preserve and update only the main version entry", func(t *testing.T) {
		api := &apidef.APIDefinition{}

		mainVersion := requireMainVersion(api)
		require.Empty(t, mainVersion.Name)
		require.Contains(t, api.VersionData.Versions, Main)

		api.VersionData.Versions["v2"] = apidef.VersionInfo{Name: "v2"}
		updatedMain := mainVersion
		updatedMain.Name = "main"
		updatedMain.GlobalHeaders = map[string]string{"X-Test": "true"}

		updateMainVersion(api, updatedMain)

		assert.Equal(t, updatedMain, requireMainVersion(api))
		assert.Equal(t, apidef.VersionInfo{Name: "v2"}, api.VersionData.Versions["v2"])

		again := requireMainVersion(api)
		assert.Equal(t, updatedMain, again)
		assert.Len(t, api.VersionData.Versions, 2)
	})
}
