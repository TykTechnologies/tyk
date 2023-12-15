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

	th := TransformHeaders{}
	th.Spec = &APISpec{APIDefinition: &apidef.APIDefinition{}}
	th.Spec.VersionData.Versions = versions

	assert.False(t, th.EnabledForSpec())

	// version level add headers
	versionInfo.GlobalHeaders["a"] = "b"
	assert.True(t, versionInfo.GlobalHeadersEnabled())
	assert.True(t, th.EnabledForSpec())
}

func TestVersionInfoGlobalHeadersEnabled(t *testing.T) {
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
