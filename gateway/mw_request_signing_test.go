package gateway

import (
	"encoding/json"
	"testing"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

var algoList = [4]string{"hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512"}

func generateSpec(algo string) {
	sessionKey := CreateSession(func(s *user.SessionState) {
		s.HMACEnabled = true
		s.HmacSecret = "9879879878787878"

		s.AccessRights = map[string]user.AccessDefinition{"protected": {APIID: "protected", Versions: []string{"v1"}}}

	})

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "protected"
		spec.Name = "protected api"
		spec.Proxy.ListenPath = "/something"
		spec.EnableSignatureChecking = true
		spec.Auth.AuthHeaderName = "authorization"
		spec.HmacAllowedClockSkew = 5000
		spec.UseKeylessAccess = false
		spec.UseBasicAuth = false
		spec.UseOauth2 = false

		version := spec.VersionData.Versions["v1"]
		version.UseExtendedPaths = true
		spec.VersionData.Versions["v1"] = version
	}, func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.RequestSigning.IsEnabled = true
		spec.RequestSigning.KeyId = sessionKey
		spec.RequestSigning.Secret = "9879879878787878"
		spec.RequestSigning.Algorithm = algo

		version := spec.VersionData.Versions["v1"]
		json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "extended_paths": {
                    "url_rewrites": [{
                        "path": "/by_name",
                        "match_pattern": "/by_name(.*)",
                        "method": "GET",
                        "rewrite_to": "tyk://protected api/get"
                    }]
                }
            }`), &version)

		spec.VersionData.Versions["v1"] = version
	})

}

func TestRequestSigning(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	for _, algo := range algoList {
		name := "Test with " + algo
		t.Run(name, func(t *testing.T) {

			generateSpec(algo)

			ts.Run(t, []test.TestCase{
				{Path: "/test/by_name", Code: 200},
			}...)
		})
	}

	t.Run("Invalid algorithm", func(t *testing.T) {
		generateSpec("random")

		ts.Run(t, []test.TestCase{
			{Path: "/test/by_name", Code: 500},
		}...)
	})

	t.Run("Invalid Date field", func(t *testing.T) {
		generateSpec("hmac-sha1")

		headers := map[string]string{"date": "Mon, 02 Jan 2006 15:04:05 GMT"}

		ts.Run(t, []test.TestCase{
			{Path: "/test/by_name", Headers: headers, Code: 400},
		}...)
	})
}
