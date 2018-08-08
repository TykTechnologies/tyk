package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func genAuthHeader(username, password string) string {
	toEncode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(toEncode))
	return fmt.Sprintf("Basic %s", encodedPass)
}

func testPrepareBasicAuth(cacheDisabled bool) *user.SessionState {
	session := createStandardSession()
	session.BasicAuthData.Password = "password"
	session.AccessRights = map[string]user.AccessDefinition{"test": {APIID: "test", Versions: []string{"v1"}}}
	session.OrgID = "default"

	buildAndLoadAPI(func(spec *APISpec) {
		spec.UseBasicAuth = true
		spec.BasicAuth.DisableCaching = cacheDisabled
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
		spec.OrgID = "default"
	})

	return session
}

func TestBasicAuth(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	session := testPrepareBasicAuth(false)

	validPassword := map[string]string{"Authorization": genAuthHeader("user", "password")}
	wrongPassword := map[string]string{"Authorization": genAuthHeader("user", "wrong")}
	wrongFormat := map[string]string{"Authorization": genAuthHeader("user", "password:more")}
	malformed := map[string]string{"Authorization": "not base64"}

	ts.Run(t, []test.TestCase{
		// Create base auth based key
		{Method: "POST", Path: "/tyk/keys/defaultuser", Data: session, AdminAuth: true, Code: 200},
		{Method: "GET", Path: "/", Code: 401, BodyMatch: `Authorization field missing`},
		{Method: "GET", Path: "/", Headers: validPassword, Code: 200},
		{Method: "GET", Path: "/", Headers: wrongPassword, Code: 401},
		{Method: "GET", Path: "/", Headers: wrongFormat, Code: 400, BodyMatch: `Attempted access with malformed header, values not in basic auth format`},
		{Method: "GET", Path: "/", Headers: malformed, Code: 400, BodyMatch: `Attempted access with malformed header, auth data not encoded correctly`},
	}...)
}

func BenchmarkBasicAuth(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	session := testPrepareBasicAuth(false)

	validPassword := map[string]string{"Authorization": genAuthHeader("user", "password")}
	wrongPassword := map[string]string{"Authorization": genAuthHeader("user", "wrong")}
	wrongFormat := map[string]string{"Authorization": genAuthHeader("user", "password:more")}
	malformed := map[string]string{"Authorization": "not base64"}

	// Create base auth based key
	ts.Run(b, test.TestCase{
		Method:    "POST",
		Path:      "/tyk/keys/defaultuser",
		Data:      session,
		AdminAuth: true,
		Code:      200,
	})

	for i := 0; i < b.N; i++ {
		ts.Run(b, []test.TestCase{
			{Method: "GET", Path: "/", Code: 401, BodyMatch: `Authorization field missing`},
			{Method: "GET", Path: "/", Headers: validPassword, Code: 200},
			{Method: "GET", Path: "/", Headers: wrongPassword, Code: 401},
			{Method: "GET", Path: "/", Headers: wrongFormat, Code: 400, BodyMatch: `Attempted access with malformed header, values not in basic auth format`},
			{Method: "GET", Path: "/", Headers: malformed, Code: 400, BodyMatch: `Attempted access with malformed header, auth data not encoded correctly`},
		}...)
	}
}

func BenchmarkBasicAuth_CacheEnabled(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	session := testPrepareBasicAuth(false)

	validPassword := map[string]string{"Authorization": genAuthHeader("user", "password")}

	// Create base auth based key
	ts.Run(b, test.TestCase{
		Method:    "POST",
		Path:      "/tyk/keys/defaultuser",
		Data:      session,
		AdminAuth: true,
		Code:      200,
	})

	for i := 0; i < b.N; i++ {
		ts.Run(b, []test.TestCase{
			{Method: "GET", Path: "/", Headers: validPassword, Code: 200},
		}...)
	}
}

func BenchmarkBasicAuth_CacheDisabled(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	session := testPrepareBasicAuth(true)

	validPassword := map[string]string{"Authorization": genAuthHeader("user", "password")}

	// Create base auth based key
	ts.Run(b, test.TestCase{
		Method:    "POST",
		Path:      "/tyk/keys/defaultuser",
		Data:      session,
		AdminAuth: true,
		Code:      200,
	})

	for i := 0; i < b.N; i++ {
		ts.Run(b, []test.TestCase{
			{Method: "GET", Path: "/", Headers: validPassword, Code: 200},
		}...)
	}
}
