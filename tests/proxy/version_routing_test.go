package proxy

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

func TestVersionRouting(t *testing.T) {
	ts := gateway.StartTest(nil)
	defer ts.Close()

	const (
		baseVersionName = "base-version-name"
		v1APIID         = "v1-api-id"
		v1VersionName   = "v1-version-name"
		v2APIID         = "v2-api-id"
		v2VersionName   = "v2-version-name"
	)

	baseAPI := gateway.BuildAPI(func(a *gateway.APISpec) {
		a.APIID = "base"
		a.Proxy.ListenPath = "/default"
		a.UseKeylessAccess = true
		a.VersionDefinition.Enabled = true
		a.VersionDefinition.Name = baseVersionName
		a.VersionDefinition.Default = apidef.Self
		a.VersionDefinition.Location = apidef.URLLocation
		a.VersionDefinition.Key = "version"
		a.VersionDefinition.Versions = map[string]string{
			v1VersionName: v1APIID,
			v2VersionName: v2APIID,
		}
	})[0]

	v1 := gateway.BuildAPI(func(a *gateway.APISpec) {
		a.APIID = v1APIID
		a.Name = "v1-version-name"
		a.Proxy.ListenPath = "/v1-version-name/listen-path-1"
		a.UseKeylessAccess = true
	})[0]

	v2 := gateway.BuildAPI(func(a *gateway.APISpec) {
		a.APIID = v2APIID
		a.Name = "v2"
		a.Proxy.ListenPath = "/v2/listen-path-2"
		a.UseKeylessAccess = true
	})[0]

	ts.Gw.LoadAPI(baseAPI, v1, v2)

	t.Run("simple versions from URL are hit", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{Path: "/default/v1-version-name", Code: http.StatusOK})
	})

	t.Run("non registered versions are not found", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{Path: "/default/v2", Code: http.StatusNotFound})
	})

	t.Run("versioning only works if urlPattern is matched", func(t *testing.T) {
		const (
			v1ShortName  = "v1"
			v1RegexAPIID = "v1-regex-api-id"
		)

		baseAPI := gateway.BuildAPI(func(a *gateway.APISpec) {
			a.APIID = "base"
			a.Proxy.ListenPath = "/default"
			a.UseKeylessAccess = true
			a.VersionDefinition.Enabled = true
			a.VersionDefinition.Name = baseVersionName
			a.VersionDefinition.Default = apidef.Self
			a.VersionDefinition.Location = apidef.URLLocation
			a.VersionDefinition.Key = "version"
			a.VersionDefinition.Versions = map[string]string{
				v1ShortName: v1RegexAPIID,
			}
			a.VersionDefinition.UrlVersioningPattern = "v\\d+"
		})[0]

		v1 := gateway.BuildAPI(func(a *gateway.APISpec) {
			a.APIID = v1RegexAPIID
			a.Name = v1ShortName
			a.Proxy.ListenPath = "/v1/listen-path-1"
			a.UseKeylessAccess = true
		})[0]

		ts.Gw.LoadAPI(baseAPI, v1)

		_, _ = ts.Run(t, test.TestCase{Path: "/default/v1", Code: http.StatusOK})
		_, _ = ts.Run(t, test.TestCase{Path: "/default/v2abc", Code: http.StatusNotFound})

	})

}
