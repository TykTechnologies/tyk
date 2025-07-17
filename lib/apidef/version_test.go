package apidef

import (
	"fmt"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

func TestVersionParameter_String(t *testing.T) {
	assert.Equal(t, "base_api_id", BaseAPIID.String())
	assert.Equal(t, "base_api_version_name", BaseAPIVersionName.String())
	assert.Equal(t, "new_version_name", NewVersionName.String())
	assert.Equal(t, "setDefault", SetDefault.String())
}

func TestVersionQueryParameters_Validate(t *testing.T) {
	baseApiExists := func(exists bool, name string) func() (bool, string) {
		return func() (bool, string) {
			return exists, name
		}
	}

	existentApiName := "existing-api"
	nonExistentApiName := "non-existent-api"

	t.Run("Empty base ID", func(t *testing.T) {
		queryParams := &VersionQueryParameters{
			versionParams: map[string]string{
				BaseAPIID.String(): "",
			},
		}
		err := queryParams.Validate(baseApiExists(false, ""))
		assert.NoError(t, err)
	})

	t.Run("Non-existent base API", func(t *testing.T) {
		queryParams := &VersionQueryParameters{
			versionParams: map[string]string{
				BaseAPIID.String(): nonExistentApiName,
			},
		}
		err := queryParams.Validate(baseApiExists(false, nonExistentApiName))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("%s is not a valid Base API version", nonExistentApiName))
	})

	t.Run("Missing version name - empty base name", func(t *testing.T) {
		queryParams := &VersionQueryParameters{
			versionParams: map[string]string{
				BaseAPIID.String():          existentApiName,
				BaseAPIVersionName.String(): "",
			},
		}
		err := queryParams.Validate(baseApiExists(true, ""))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("you need to provide a version name for the new Base API: %s", existentApiName))
	})

	t.Run("Missing version name - non empty base name", func(t *testing.T) {
		queryParams := &VersionQueryParameters{
			versionParams: map[string]string{
				BaseAPIID.String():          existentApiName,
				BaseAPIVersionName.String(): "",
			},
		}
		err := queryParams.Validate(baseApiExists(true, "baseID"))
		assert.NoError(t, err)
	})

	t.Run("Valid parameters", func(t *testing.T) {
		queryParams := &VersionQueryParameters{
			versionParams: map[string]string{
				BaseAPIID.String():          existentApiName,
				BaseAPIVersionName.String(): "v1",
			},
		}
		err := queryParams.Validate(baseApiExists(true, "v1"))
		assert.NoError(t, err)
	})
}

func TestVersionQueryParameters_IsEmpty(t *testing.T) {
	queryParams := &VersionQueryParameters{
		versionParams: map[string]string{
			BaseAPIID.String():          "api-123",
			BaseAPIVersionName.String(): "v1",
			NewVersionName.String():     "",
		},
	}

	assert.False(t, queryParams.IsEmpty(BaseAPIID))
	assert.False(t, queryParams.IsEmpty(BaseAPIVersionName))

	assert.True(t, queryParams.IsEmpty(NewVersionName))
	assert.True(t, queryParams.IsEmpty(SetDefault))
}

func TestVersionQueryParameters_Get(t *testing.T) {
	queryParams := &VersionQueryParameters{
		versionParams: map[string]string{
			BaseAPIID.String():          "api-123",
			BaseAPIVersionName.String(): "v1",
		},
	}

	assert.Equal(t, "api-123", queryParams.Get(BaseAPIID))
	assert.Equal(t, "v1", queryParams.Get(BaseAPIVersionName))

	assert.Empty(t, queryParams.Get(NewVersionName))
}

func TestAllVersionParameters(t *testing.T) {
	params := AllVersionParameters()
	assert.Len(t, params, int(paramCount))
	assert.Contains(t, params, BaseAPIID)
	assert.Contains(t, params, BaseAPIVersionName)
	assert.Contains(t, params, NewVersionName)
	assert.Contains(t, params, SetDefault)
}

func TestNewVersionQueryParameters(t *testing.T) {
	baseAPIID := "api-123"
	baseVersion := "v1"
	newVersion := "v2"
	setDefault := "true"

	u, _ := url.Parse(fmt.Sprintf("http://example.com/api?base_api_id=%s&base_api_version_name=%s&new_version_name=%s&setDefault=%s", baseAPIID, baseVersion, newVersion, setDefault))
	req := &http.Request{
		URL: u,
	}

	queryParams := NewVersionQueryParameters(req.URL.Query())

	assert.Equal(t, baseAPIID, queryParams.Get(BaseAPIID))
	assert.Equal(t, baseVersion, queryParams.Get(BaseAPIVersionName))
	assert.Equal(t, newVersion, queryParams.Get(NewVersionName))
	assert.Equal(t, setDefault, queryParams.Get(SetDefault))
}

func TestConfigureVersionDefinition(t *testing.T) {
	baseName := "v1"
	versionName := "v2"
	apiID := "api-123"

	t.Run("Basic configuration", func(t *testing.T) {
		baseDefinition := apidef.VersionDefinition{}
		versionParams := &VersionQueryParameters{
			versionParams: map[string]string{
				BaseAPIVersionName.String(): baseName,
				NewVersionName.String():     versionName,
			},
		}

		result := ConfigureVersionDefinition(baseDefinition, versionParams, apiID)

		assert.True(t, result.Enabled)
		assert.Equal(t, baseName, result.Name)
		assert.Equal(t, apidef.DefaultAPIVersionKey, result.Key)
		assert.Equal(t, apidef.HeaderLocation, result.Location)
		assert.Equal(t, apidef.Self, result.Default)
		assert.Equal(t, apiID, result.Versions[versionName])
	})

	t.Run("With set default", func(t *testing.T) {
		baseDefinition := apidef.VersionDefinition{}
		versionParams := &VersionQueryParameters{
			versionParams: map[string]string{
				NewVersionName.String(): versionName,
				SetDefault.String():     "true",
			},
		}

		result := ConfigureVersionDefinition(baseDefinition, versionParams, apiID)

		assert.Equal(t, versionName, result.Default)
		assert.Equal(t, apiID, result.Versions[versionName])
	})
}
