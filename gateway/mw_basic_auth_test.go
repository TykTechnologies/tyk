package gateway

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func genAuthHeader(username, password string) string {
	toEncode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(toEncode))
	return fmt.Sprintf("Basic %s", encodedPass)
}

func (ts *Test) testPrepareBasicAuth(cacheDisabled bool) *user.SessionState {

	session := CreateStandardSession()
	session.BasicAuthData.Password = "password"
	session.AccessRights = map[string]user.AccessDefinition{"test": {APIID: "test", Versions: []string{"v1"}}}
	session.OrgID = "default"

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseBasicAuth = true
		spec.BasicAuth.DisableCaching = cacheDisabled
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
		spec.OrgID = "default"
	})

	return session
}

func TestBasicAuth(t *testing.T) {
	test.Flaky(t) // TODO: TT-5223

	ts := StartTest(nil)
	defer ts.Close()

	session := ts.testPrepareBasicAuth(false)

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

func TestBasicAuthFromBody(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	session := CreateStandardSession()
	session.BasicAuthData.Password = "password"
	session.AccessRights = map[string]user.AccessDefinition{"test": {APIID: "test", Versions: []string{"v1"}}}
	session.OrgID = "default"

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseBasicAuth = true
		spec.BasicAuth.ExtractFromBody = true
		spec.BasicAuth.BodyUserRegexp = `<User>(.*)</User>`
		spec.BasicAuth.BodyPasswordRegexp = `<Password>(.*)</Password>`
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
		spec.OrgID = "default"
	})

	validPassword := `<User>user</User><Password>password</Password>`
	wrongPassword := `<User>user</User><Password>wrong</Password>`
	withoutPassword := `<User>user</User>`
	malformed := `<User>User>`
	emptyAuthHeader := map[string]string{"Www-Authenticate": ""}

	ts.Run(t, []test.TestCase{
		// Create base auth based key
		{Method: "POST", Path: "/tyk/keys/defaultuser", Data: session, AdminAuth: true, Code: 200},
		{Method: "POST", Path: "/", Code: 400, BodyMatch: `Body do not contain username`},
		{Method: "POST", Path: "/", Data: validPassword, Code: 200, HeadersMatch: emptyAuthHeader},
		{Method: "POST", Path: "/", Data: wrongPassword, Code: 401},
		{Method: "POST", Path: "/", Data: withoutPassword, Code: 400, BodyMatch: `Body do not contain password`},
		{Method: "GET", Path: "/", Data: malformed, Code: 400, BodyMatch: `Body do not contain username`},
	}...)
}

func TestBasicAuthLegacyWithHashFunc(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()

	globalConf.HashKeys = true
	globalConf.EnableHashedKeysListing = true
	// settings to create BA session with legacy key format
	globalConf.HashKeyFunction = ""
	ts.Gw.SetConfig(globalConf)

	// create session with legacy key format
	session := ts.testPrepareBasicAuth(false)

	validPassword := map[string]string{"Authorization": genAuthHeader("user", "password")}

	ts.Run(t, []test.TestCase{
		// Create base auth based key
		{Method: "POST", Path: "/tyk/keys/defaultuser", Data: session, AdminAuth: true, Code: 200},
		{Method: "GET", Path: "/", Headers: validPassword, Code: 200},
	}...)

	// set custom hashing function and check if we still do BA session auth with legacy key format
	globalConf.HashKeyFunction = storage.HashMurmur64
	ts.Gw.SetConfig(globalConf)

	ts.Run(t, []test.TestCase{
		// Create base auth based key
		{Method: "GET", Path: "/", Headers: validPassword, Code: 200},
	}...)
}

func TestBasicAuthHashKeyFunc(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()

	globalConf.HashKeys = true
	globalConf.EnableHashedKeysListing = true
	// settings to create BA session with legacy key format
	globalConf.HashKeyFunction = ""

	testcases := []struct {
		in, out string
	}{
		{"", "bcrypt"},
		{"bcrypt", "bcrypt"},
		{"sha256", "sha256"},
		{"murmur32", "murmur32"},
		{"murmur64", "murmur64"},
		{"murmur128", "murmur128"},
		{"invalid", "bcrypt"},
	}

	logger := log.WithField("test", "TestBasicAuthHashKeyFunc")

	for idx, hashKeyFunc := range testcases {
		t.Run(fmt.Sprintf("test case %d", idx), func(t *testing.T) {
			globalConf.BasicAuthHashKeyFunction = hashKeyFunc.in
			ts.Gw.SetConfig(globalConf)

			session := ts.testPrepareBasicAuth(false)
			ts.Gw.setBasicAuthSessionPassword(session)

			assert.Equal(t, hashKeyFunc.out, string(session.BasicAuthData.Hash))
			assert.NotEmpty(t, session.BasicAuthData.Password)

			ts.Gw.apisMu.Lock()
			assert.Len(t, ts.Gw.apiSpecs, 1)
			k := &BasicAuthKeyIsValid{}
			k.Spec = ts.Gw.apiSpecs[0]
			ts.Gw.apisMu.Unlock()

			err := k.checkPassword(session, "password", logger)
			assert.NoError(t, err)
		})
	}

}

func TestBasicAuthCachedUserCollision(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.HashKeys = true
	globalConf.HashKeyFunction = "murmur64"
	ts.Gw.SetConfig(globalConf)

	session := ts.testPrepareBasicAuth(false)

	correct := map[string]string{"Authorization": genAuthHeader("bellbell1", "password")}
	remove1 := map[string]string{"Authorization": genAuthHeader("bellbell", "password")}
	remove2 := map[string]string{"Authorization": genAuthHeader("bellbel", "password")}
	remove3 := map[string]string{"Authorization": genAuthHeader("bellbe", "password")}
	remove4 := map[string]string{"Authorization": genAuthHeader("bellb", "password")}
	remove5 := map[string]string{"Authorization": genAuthHeader("bell", "password")}
	add1 := map[string]string{"Authorization": genAuthHeader("bellbell11", "password")}
	add2 := map[string]string{"Authorization": genAuthHeader("bellbell12", "password")}
	add3 := map[string]string{"Authorization": genAuthHeader("bellbell13", "password")}

	ts.Run(t, []test.TestCase{
		// Create base auth based key
		{Method: "POST", Path: "/tyk/keys/bellbell1", Data: session, AdminAuth: true, Code: http.StatusOK},
		{Method: "GET", Path: "/", Headers: correct, Code: http.StatusOK},
		{Method: "GET", Path: "/", Headers: remove1, Code: http.StatusUnauthorized},
		{Method: "GET", Path: "/", Headers: remove2, Code: http.StatusUnauthorized},
		{Method: "GET", Path: "/", Headers: remove3, Code: http.StatusUnauthorized},
		{Method: "GET", Path: "/", Headers: remove4, Code: http.StatusUnauthorized},
		{Method: "GET", Path: "/", Headers: remove5, Code: http.StatusUnauthorized},
		{Method: "GET", Path: "/", Headers: add1, Code: http.StatusUnauthorized},
		{Method: "GET", Path: "/", Headers: add2, Code: http.StatusUnauthorized},
		{Method: "GET", Path: "/", Headers: add3, Code: http.StatusUnauthorized},
		{Method: "GET", Path: "/", Headers: correct, Code: http.StatusOK},
	}...)
}

func TestBasicAuthCachedPasswordCollision(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	for _, useCache := range []bool{true, false} {
		correct := map[string]string{"Authorization": genAuthHeader("bellbell1", "password")}
		remove1 := map[string]string{"Authorization": genAuthHeader("bellbell1", "passwor")}
		remove2 := map[string]string{"Authorization": genAuthHeader("bellbell1", "passwo")}
		remove3 := map[string]string{"Authorization": genAuthHeader("bellbell1", "passw")}
		remove4 := map[string]string{"Authorization": genAuthHeader("bellbell1", "pass")}
		remove5 := map[string]string{"Authorization": genAuthHeader("bellbell1", "pas")}
		add1 := map[string]string{"Authorization": genAuthHeader("bellbell1", "password1")}
		add2 := map[string]string{"Authorization": genAuthHeader("bellbell1", "password22")}
		add3 := map[string]string{"Authorization": genAuthHeader("bellbell1", "password333")}

		t.Run(fmt.Sprintf("Cache disabled:%v", useCache), func(t *testing.T) {
			session := ts.testPrepareBasicAuth(useCache)

			ts.Run(t, []test.TestCase{
				// Create base auth based key
				{Method: "POST", Path: "/tyk/keys/bellbell1", Data: session, AdminAuth: true, Code: http.StatusOK},
				{Method: "GET", Path: "/", Headers: correct, Code: http.StatusOK},
				{Method: "GET", Path: "/", Headers: remove1, Code: http.StatusUnauthorized},
				{Method: "GET", Path: "/", Headers: remove2, Code: http.StatusUnauthorized},
				{Method: "GET", Path: "/", Headers: remove3, Code: http.StatusUnauthorized},
				{Method: "GET", Path: "/", Headers: remove4, Code: http.StatusUnauthorized},
				{Method: "GET", Path: "/", Headers: remove5, Code: http.StatusUnauthorized},
				{Method: "GET", Path: "/", Headers: add1, Code: http.StatusUnauthorized},
				{Method: "GET", Path: "/", Headers: add2, Code: http.StatusUnauthorized},
				{Method: "GET", Path: "/", Headers: add3, Code: http.StatusUnauthorized},
				{Method: "GET", Path: "/", Headers: correct, Code: http.StatusOK},
			}...)
		})
	}
}

func BenchmarkBasicAuth(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest(nil)
	defer ts.Close()

	session := ts.testPrepareBasicAuth(false)

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

	ts := StartTest(nil)
	defer ts.Close()

	session := ts.testPrepareBasicAuth(false)

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

	ts := StartTest(nil)
	defer ts.Close()

	session := ts.testPrepareBasicAuth(true)

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
