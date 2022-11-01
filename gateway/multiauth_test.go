package gateway

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/justinas/alice"
	"github.com/lonelycode/go-uuid/uuid"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

const multiAuthDev = `{
	"api_id": "55",
	"org_id": "default",
	"use_basic_auth": true,
	"use_standard_auth": true,
	"base_identity_provided_by": "auth_token",
	"auth_configs": {
		"basic": {"auth_header_name": "Authorization"},
		"authToken": {"auth_header_name": "x-standard-auth"}
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + TestHttpAny + `"
	}
}`

func createMultiAuthKeyAuthSession(isBench bool) *user.SessionState {
	session := user.NewSessionState()
	session.Rate = 100.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	if isBench {
		session.QuotaRemaining = 100000000
		session.QuotaMax = 100000000
	} else {
		session.QuotaRemaining = 900
		session.QuotaMax = 10
	}
	session.AccessRights = map[string]user.AccessDefinition{"55": {APIName: "Tyk Multi Key Test", APIID: "55", Versions: []string{"default"}}}
	return session
}

func createMultiBasicAuthSession(isBench bool) *user.SessionState {
	session := user.NewSessionState()
	session.Rate = 8.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix() + 20
	session.QuotaRemaining = 1
	session.QuotaMax = -1
	session.BasicAuthData.Password = "TEST"
	session.AccessRights = map[string]user.AccessDefinition{"55": {APIName: "Tyk Multi Key Test", APIID: "55", Versions: []string{"default"}}}
	return session
}

func (ts *Test) getMultiAuthStandardAndBasicAuthChain(spec *APISpec) http.Handler {

	remote, _ := url.Parse(TestHttpAny)
	proxy := ts.Gw.TykNewSingleHostReverseProxy(remote, spec, nil)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{Spec: spec, Proxy: proxy, Gw: ts.Gw}
	chain := alice.New(ts.Gw.mwList(
		&IPWhiteListMiddleware{baseMid},
		&IPBlackListMiddleware{BaseMiddleware: baseMid},
		&BasicAuthKeyIsValid{baseMid, nil, nil},
		&AuthKey{baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
		&KeyExpired{baseMid},
		&AccessRightsCheck{baseMid},
		&RateLimitAndQuotaCheck{baseMid},
	)...).Then(proxyHandler)
	return chain
}

func (ts *Test) testPrepareMultiSessionBA(t testing.TB, isBench bool) (*APISpec, *http.Request) {

	spec := ts.Gw.LoadSampleAPI(multiAuthDev)

	// Create BA
	baSession := createMultiBasicAuthSession(isBench)
	username := ""
	if isBench {
		username = uuid.New()
	} else {
		username = "0987876"
	}
	password := "TEST"
	keyName := ts.Gw.generateToken("default", username)
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	err := ts.Gw.GlobalSessionManager.UpdateSession(keyName, baSession, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	// Create key
	session := createMultiAuthKeyAuthSession(isBench)
	customToken := ""
	if isBench {
		customToken = uuid.New()
	} else {
		customToken = "84573485734587384888723487243"
	}
	// AuthKey sessions are stored by {token}
	err = ts.Gw.GlobalSessionManager.UpdateSession(customToken, session, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	toEncode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(toEncode))

	req := TestReq(t, "GET", "/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))
	req.Header.Set("x-standard-auth", fmt.Sprintf("Bearer %s", customToken))

	return spec, req
}

func TestMultiSession_BA_Standard_OK(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	spec, req := ts.testPrepareMultiSessionBA(t, false)

	recorder := httptest.NewRecorder()
	chain := ts.getMultiAuthStandardAndBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func BenchmarkMultiSession_BA_Standard_OK(b *testing.B) {
	ts := StartTest(nil)
	defer ts.Close()

	b.ReportAllocs()

	spec, req := ts.testPrepareMultiSessionBA(b, true)

	recorder := httptest.NewRecorder()
	chain := ts.getMultiAuthStandardAndBasicAuthChain(spec)

	for i := 0; i < b.N; i++ {
		chain.ServeHTTP(recorder, req)
		if recorder.Code != 200 {
			b.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
		}
	}
}

func TestMultiSession_BA_Standard_Identity(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI(multiAuthDev)

	// Create BA
	baSession := createMultiBasicAuthSession(false)
	username := "0987876"
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	err := ts.Gw.GlobalSessionManager.UpdateSession("default0987876", baSession, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	// Create key
	session := createMultiAuthKeyAuthSession(false)
	customToken := "84573485734587384888723487243"
	// AuthKey sessions are stored by {token}
	err = ts.Gw.GlobalSessionManager.UpdateSession(customToken, session, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	to_encode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))

	recorder := httptest.NewRecorder()
	req := TestReq(t, "GET", "/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))
	req.Header.Set("x-standard-auth", fmt.Sprintf("Bearer %s", customToken))

	chain := ts.getMultiAuthStandardAndBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}

	if recorder.Header().Get("X-Ratelimit-Remaining") == "-1" {
		t.Error("Expected quota limit but found -1, wrong base identity became context")
		t.Error(recorder.Header().Get("X-Ratelimit-Remaining"))
	}
}

func TestMultiSession_BA_Standard_FailBA(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI(multiAuthDev)

	// Create BA
	baSession := createMultiBasicAuthSession(false)
	username := "0987876"
	password := "WRONG"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	err := ts.Gw.GlobalSessionManager.UpdateSession("default0987876", baSession, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	// Create key
	session := createMultiAuthKeyAuthSession(false)
	customToken := "84573485734587384888723487243"
	// AuthKey sessions are stored by {token}
	err = ts.Gw.GlobalSessionManager.UpdateSession(customToken, session, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	to_encode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))

	recorder := httptest.NewRecorder()
	req := TestReq(t, "GET", "/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))
	req.Header.Set("x-standard-auth", fmt.Sprintf("Bearer %s", customToken))

	chain := ts.getMultiAuthStandardAndBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 401 {
		t.Error("Wrong response code received, expected 401: \n", recorder.Code)
	}
}

func TestMultiSession_BA_Standard_FailStandard(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI(multiAuthDev)

	// Create BA
	baSession := createMultiBasicAuthSession(false)
	username := "0987876"
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	err := ts.Gw.GlobalSessionManager.UpdateSession("default0987876", baSession, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	// Create key
	session := createMultiAuthKeyAuthSession(false)
	customToken := "84573485734587384888723487243"
	// AuthKey sessions are stored by {token}
	err = ts.Gw.GlobalSessionManager.UpdateSession(customToken, session, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	to_encode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))

	recorder := httptest.NewRecorder()
	req := TestReq(t, "GET", "/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))
	req.Header.Set("x-standard-auth", fmt.Sprintf("Bearer %s", "WRONGTOKEN"))

	chain := ts.getMultiAuthStandardAndBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Wrong response code received, expected 403: \n", recorder.Code)
	}
}

func TestJWTAuthKeyMultiAuth(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	pID := ts.CreatePolicy()

	spec := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false

		spec.AuthConfigs = make(map[string]apidef.AuthConfig)

		spec.UseStandardAuth = true
		authConfig := spec.AuthConfigs["authToken"]
		authConfig.AuthHeaderName = "Auth-Token"
		spec.AuthConfigs["authToken"] = authConfig
		spec.BaseIdentityProvidedBy = apidef.AuthToken

		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		jwtConfig := spec.AuthConfigs["jwt"]
		jwtConfig.AuthHeaderName = "Auth-JWT"
		spec.AuthConfigs["jwt"] = jwtConfig
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.JWTDefaultPolicies = []string{pID}

		spec.Proxy.ListenPath = "/"
	})[0]

	ts.Gw.LoadAPI(spec)

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	key := CreateSession(ts.Gw)

	ts.Run(t, []test.TestCase{
		{
			Headers: map[string]string{"Auth-JWT": jwtToken, "Auth-Token": key},
			Code:    http.StatusOK,
		},
		{
			Headers: map[string]string{"Auth-JWT": jwtToken, "Auth-Token": key},
			Code:    http.StatusOK,
		},
		{
			Headers:   map[string]string{"Auth-JWT": jwtToken},
			Code:      http.StatusUnauthorized,
			BodyMatch: "Authorization field missing",
		},
		{
			Headers:   map[string]string{"Auth-Token": key},
			Code:      http.StatusBadRequest,
			BodyMatch: "Authorization field missing",
		},
		{
			Headers:   map[string]string{"Auth-JWT": "junk", "Auth-Token": key},
			Code:      http.StatusForbidden,
			BodyMatch: "Key not authorized",
		},
	}...)
}
