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
	assert.True(t, th.EnabledForSpec())
	versionInfo.GlobalHeadersDisabled = true
	versions["Default"] = versionInfo
	assert.False(t, th.EnabledForSpec())

	// reset
	versionInfo.GlobalResponseHeaders = map[string]string{}
	versionInfo.GlobalHeadersDisabled = false
	versions["Default"] = versionInfo

	// version level remove headers
	versionInfo.GlobalResponseHeadersRemove = []string{"a"}
	assert.True(t, th.EnabledForSpec())
	versionInfo.GlobalHeadersDisabled = true
	versions["Default"] = versionInfo
	assert.False(t, th.EnabledForSpec())
}
