package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestTransformHeaders_EnabledForSpec(t *testing.T) {
	versionInfo := apidef.VersionInfo{
		GlobalHeaders: map[string]string{},
	}

	versions := map[string]apidef.VersionInfo{
		"Default": versionInfo,
	}

	th := TransformHeaders{BaseMiddleware: &BaseMiddleware{}}
	th.Spec = &APISpec{APIDefinition: &apidef.APIDefinition{}}
	th.Spec.VersionData.Versions = versions

	assert.False(t, th.EnabledForSpec())

	// version level add headers
	versionInfo.GlobalHeaders["a"] = "b"
	assert.True(t, versionInfo.GlobalHeadersEnabled())
	assert.True(t, th.EnabledForSpec())

	versionInfo.GlobalHeaders = nil
	versions["Default"] = versionInfo
	assert.False(t, th.EnabledForSpec())

	// endpoint level add headers
	versionInfo.UseExtendedPaths = true
	versionInfo.ExtendedPaths.TransformHeader = []apidef.HeaderInjectionMeta{{Disabled: false, DeleteHeaders: []string{"a"}}}
	versions["Default"] = versionInfo
	assert.True(t, th.EnabledForSpec())
}

func TestVersionInfo_GlobalHeadersEnabled(t *testing.T) {
	v := apidef.VersionInfo{
		GlobalHeaders:       map[string]string{},
		GlobalHeadersRemove: []string{},
	}

	assert.False(t, v.GlobalHeadersEnabled())

	// add headers
	v.GlobalHeaders["a"] = "b"
	assert.True(t, v.GlobalHeadersEnabled())
	v.GlobalHeadersDisabled = true
	assert.False(t, v.GlobalHeadersEnabled())

	// reset
	v.GlobalHeaders = map[string]string{}
	v.GlobalHeadersDisabled = false
	assert.False(t, v.GlobalHeadersEnabled())

	// remove headers
	v.GlobalHeadersRemove = []string{"a"}
	assert.True(t, v.GlobalHeadersEnabled())
	v.GlobalHeadersDisabled = true
	assert.False(t, v.GlobalHeadersEnabled())
}

func TestVersionInfo_HasEndpointReqHeader(t *testing.T) {
	v := apidef.VersionInfo{}

	assert.False(t, v.HasEndpointReqHeader())
	v.UseExtendedPaths = true
	assert.False(t, v.HasEndpointReqHeader())

	v.ExtendedPaths.TransformHeader = make([]apidef.HeaderInjectionMeta, 2)
	assert.False(t, v.HasEndpointReqHeader())

	v.ExtendedPaths.TransformHeader[0].Disabled = true
	v.ExtendedPaths.TransformHeader[0].AddHeaders = map[string]string{"a": "b"}
	assert.False(t, v.HasEndpointReqHeader())

	v.ExtendedPaths.TransformHeader[1].Disabled = false
	v.ExtendedPaths.TransformHeader[1].DeleteHeaders = []string{"a"}
	assert.True(t, v.HasEndpointReqHeader())
}

func TestHeaderInjectionMeta_Enabled(t *testing.T) {
	h := apidef.HeaderInjectionMeta{Disabled: true}
	assert.False(t, h.Enabled())

	h.Disabled = false
	assert.False(t, h.Enabled())

	h.AddHeaders = map[string]string{"a": "b"}
	assert.True(t, h.Enabled())

	h.AddHeaders = nil
	assert.False(t, h.Enabled())

	h.DeleteHeaders = []string{"a"}
	assert.True(t, h.Enabled())
}
