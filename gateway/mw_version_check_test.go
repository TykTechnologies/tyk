package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func testPrepareVersioning() (string, string) {
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.VersionData.NotVersioned = false
		spec.VersionDefinition.Location = "header"
		spec.VersionDefinition.Key = "version"
		spec.Proxy.ListenPath = "/"
		spec.VersionData.Versions["expired"] = apidef.VersionInfo{
			Name:    "expired",
			Expires: "2006-01-02 15:04",
		}
		spec.VersionData.Versions["v2"] = apidef.VersionInfo{
			Name:             "v2",
			UseExtendedPaths: true,
			ExtendedPaths: apidef.ExtendedPathsSet{
				WhiteList: []apidef.EndPointMeta{
					{
						Path: "/mock",
						MethodActions: map[string]apidef.EndpointMethodMeta{
							http.MethodGet: {
								Action:  apidef.Reply,
								Code:    http.StatusOK,
								Data:    "testbody",
								Headers: map[string]string{"testheader": "testvalue"},
							},
						},
					},
				},
				URLRewrite: []apidef.URLRewriteMeta{
					{
						Path:         "/a",
						Method:       http.MethodGet,
						MatchPattern: "/a(.*)",
						RewriteTo:    "/b",
					},
					{
						Path:         "/c",
						Method:       http.MethodPost,
						MatchPattern: "/c(.*)",
						RewriteTo:    "/d",
					},
				},
				Ignored: []apidef.EndPointMeta{
					{
						Path: "/ignore",
					},
				},
			},
		}
	})

	keyWrongVersion := CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v3"},
		}}
	})

	keyKnownVersion := CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1", "v2", "expired"},
		}}
	})

	return keyWrongVersion, keyKnownVersion
}

func TestVersioning(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	keyWrongVersion, keyKnownVersion := testPrepareVersioning()

	wrongVersionHeaders := map[string]string{
		"authorization": keyWrongVersion,
		"version":       "v3",
	}

	disallowedAccessHeaders := map[string]string{
		"authorization": keyWrongVersion,
		"version":       "v1",
	}

	knownVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "v1",
	}

	expiredVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "expired",
	}

	mockVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "v2",
	}

	ts.Run(t, []test.TestCase{
		{Path: "/", Code: 403, Headers: wrongVersionHeaders, BodyMatch: "This API version does not seem to exist"},
		{Path: "/", Code: 403, Headers: disallowedAccessHeaders, BodyMatch: "Access to this API has been disallowed"},
		{Path: "/", Code: 200, Headers: knownVersionHeaders},
		{Path: "/", Code: 403, Headers: expiredVersionHeaders, BodyMatch: string(VersionExpired)},
		{Path: "/mock", Code: 200, Headers: mockVersionHeaders, BodyMatch: "testbody", HeadersMatch: map[string]string{"testheader": "testvalue"}},
		{Path: "/ignore", Code: 200, Headers: mockVersionHeaders},
	}...)
}

func BenchmarkVersioning(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	keyWrongVersion, keyKnownVersion := testPrepareVersioning()
	wrongVersionHeaders := map[string]string{
		"authorization": keyWrongVersion,
		"version":       "v3",
	}

	disallowedAccessHeaders := map[string]string{
		"authorization": keyWrongVersion,
		"version":       "v1",
	}

	knownVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "v1",
	}

	expiredVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "expired",
	}
	mockVersionHeaders := map[string]string{
		"authorization": keyKnownVersion,
		"version":       "v2",
	}

	for i := 0; i < b.N; i++ {
		ts.Run(b, []test.TestCase{
			{Path: "/", Code: 403, Headers: wrongVersionHeaders, BodyMatch: "This API version does not seem to exist"},
			{Path: "/", Code: 403, Headers: disallowedAccessHeaders, BodyMatch: "Access to this API has been disallowed"},
			{Path: "/", Code: 200, Headers: knownVersionHeaders},
			{Path: "/", Code: 403, Headers: expiredVersionHeaders, BodyMatch: string(VersionExpired)},
			{Path: "/mock", Code: 200, Headers: mockVersionHeaders, BodyMatch: "testbody", HeadersMatch: map[string]string{"testheader": "testvalue"}},
			{Path: "/ignore", Code: 200, Headers: mockVersionHeaders},
		}...)
	}
}
