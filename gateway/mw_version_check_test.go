package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func (ts *Test) testPrepareVersioning() (string, string) {

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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

	keyWrongVersion := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v3"},
		}}
	})

	keyKnownVersion := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1", "v2", "expired"},
		}}
	})

	return keyWrongVersion, keyKnownVersion
}

func TestVersioning(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	keyWrongVersion, keyKnownVersion := ts.testPrepareVersioning()

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

	ts := StartTest(nil)
	defer ts.Close()

	keyWrongVersion, keyKnownVersion := ts.testPrepareVersioning()
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

func TestNotVersioned(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	api := BuildAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.VersionData.NotVersioned = false
		spec.VersionData.Versions["Default"] = apidef.VersionInfo{
			Name:           "Default",
			OverrideTarget: "www.example.com",
		}
	})[0]

	t.Run("Versioning enabled, override target URL", func(t *testing.T) {
		g.Gw.LoadAPI(api)
		_, _ = g.Run(t, test.TestCase{Code: http.StatusInternalServerError})
	})

	t.Run("Versioning disabled, use original target URL", func(t *testing.T) {
		api.VersionData.NotVersioned = true
		g.Gw.LoadAPI(api)

		_, _ = g.Run(t, test.TestCase{Code: http.StatusOK})
	})
}

func TestNewVersioning(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	versionedAPI := BuildAPI(func(a *APISpec) {
		a.APIID = "versioned"
		a.Name = "versioned"
		a.Proxy.ListenPath = "/new"
		a.UseKeylessAccess = false
		a.VersionData.DefaultVersion = ""
		a.VersionData.Versions = map[string]apidef.VersionInfo{
			"Default": {},
		}
	})[0]

	baseAPI := BuildAPI(func(a *APISpec) {
		a.APIID = "base"
		a.Proxy.ListenPath = "/default"
		a.UseKeylessAccess = true
		a.VersionData.NotVersioned = false
		a.VersionData.DefaultVersion = "v1"
		a.VersionData.Versions = map[string]apidef.VersionInfo{
			"v1": {
				Name: "v1",
			},
			"v2": {
				Name:  "v2",
				APIID: versionedAPI.APIID,
			},
		}
		a.VersionDefinition.Location = "url-param"
		a.VersionDefinition.Key = "version"
	})[0]

	ts.Gw.LoadAPI(baseAPI, versionedAPI)

	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{versionedAPI.APIID: {
			APIID: versionedAPI.APIID,
		}}
	})

	headers := map[string]string{
		"Authorization": key,
	}

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/default", Code: http.StatusOK},
		// default listen path with version param should route to v2
		{Path: "/default?version=v2", Code: http.StatusUnauthorized},
		{Path: "/default?version=v2", Headers: headers, Code: http.StatusOK},
		// For not found version, it should fallback to default
		{Path: "/default?version=notFound", BodyMatch: string(VersionDoesNotExist), Code: http.StatusForbidden},
		// v2 should be accessible by its own listen path
		{Path: "/new", Code: http.StatusUnauthorized},
		{Path: "/new", Headers: headers, Code: http.StatusOK},
	}...)

	t.Run("versioned API is not versioned", func(t *testing.T) {
		assert.True(t, versionedAPI.VersionData.NotVersioned)
		t.Run("default is not specified", func(t *testing.T) {
			assert.Empty(t, versionedAPI.VersionData.DefaultVersion)
			_, _ = ts.Run(t, test.TestCase{Path: "/default?version=v2", Headers: headers, Code: http.StatusOK})
		})

		t.Run("default is invalid", func(t *testing.T) {
			versionedAPI.VersionData.DefaultVersion = "invalid"
			ts.Gw.LoadAPI(baseAPI, versionedAPI)
			_, _ = ts.Run(t, test.TestCase{Path: "/default?version=v2", Headers: headers, Code: http.StatusOK})
		})
	})

	t.Run("versioned API is versioned", func(t *testing.T) {
		versionedAPI.VersionData.NotVersioned = false
		t.Run("default is not specified", func(t *testing.T) {
			versionedAPI.VersionData.DefaultVersion = ""
			ts.Gw.LoadAPI(baseAPI, versionedAPI)
			assert.Empty(t, versionedAPI.VersionData.DefaultVersion)
			_, _ = ts.Run(t, test.TestCase{Path: "/default?version=v2", Headers: headers,
				BodyMatch: string(VersionNotFound), Code: http.StatusForbidden})
		})

		t.Run("default is invalid", func(t *testing.T) {
			versionedAPI.VersionData.DefaultVersion = "invalid"
			ts.Gw.LoadAPI(baseAPI, versionedAPI)
			_, _ = ts.Run(t, test.TestCase{Path: "/default?version=v2", Headers: headers,
				BodyMatch: string(VersionDoesNotExist), Code: http.StatusForbidden})
		})
	})
}
