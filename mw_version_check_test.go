package main

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func testPrepareVersioning() (string, string) {
	buildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.VersionData.NotVersioned = false
		spec.VersionDefinition.Location = "header"
		spec.VersionDefinition.Key = "version"
		spec.Proxy.ListenPath = "/"
		spec.VersionData.Versions["expired"] = apidef.VersionInfo{
			Name:    "expired",
			Expires: "2006-01-02 15:04",
		}
	})

	keyWrongVersion := createSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v2"},
		}}
	})

	keyKnownVersion := createSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1", "expired"},
		}}
	})

	return keyWrongVersion, keyKnownVersion
}

func TestVersioning(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	keyWrongVersion, keyKnownVersion := testPrepareVersioning()

	wrongVersionHeaders := map[string]string{
		"authorization": keyWrongVersion,
		"version":       "v2",
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

	ts.Run(t, []test.TestCase{
		{Path: "/", Code: 403, Headers: wrongVersionHeaders, BodyMatch: "This API version does not seem to exist"},
		{Path: "/", Code: 403, Headers: disallowedAccessHeaders, BodyMatch: "Access to this API has been disallowed"},
		{Path: "/", Code: 200, Headers: knownVersionHeaders},
		{Path: "/", Code: 403, Headers: expiredVersionHeaders, BodyMatch: string(VersionExpired)},
	}...)
}

func BenchmarkVersioning(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	keyWrongVersion, keyKnownVersion := testPrepareVersioning()

	wrongVersionHeaders := map[string]string{
		"authorization": keyWrongVersion,
		"version":       "v2",
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

	for i := 0; i < b.N; i++ {
		ts.Run(b, []test.TestCase{
			{Path: "/", Code: 403, Headers: wrongVersionHeaders, BodyMatch: "This API version does not seem to exist"},
			{Path: "/", Code: 403, Headers: disallowedAccessHeaders, BodyMatch: "Access to this API has been disallowed"},
			{Path: "/", Code: 200, Headers: knownVersionHeaders},
			{Path: "/", Code: 403, Headers: expiredVersionHeaders, BodyMatch: string(VersionExpired)},
		}...)
	}
}
