package gateway

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/justinas/alice"
	"github.com/lonelycode/go-uuid/uuid"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/signature_validator"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestMurmur3CharBug(t *testing.T) {
	defer ResetTestConfig()
	ts := StartTest()
	defer ts.Close()

	api := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})[0]

	genTestCase := func(key string, status int) test.TestCase {
		return test.TestCase{Path: "/", Headers: map[string]string{"Authorization": key}, Code: status}
	}

	t.Run("Without hashing", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HashKeys = false
		config.SetGlobal(globalConf)

		LoadAPI(api)

		key := CreateSession()

		ts.Run(t, []test.TestCase{
			genTestCase("wrong", 403),
			genTestCase(key+"abc", 403),
			genTestCase(key, 200),
		}...)
	})

	t.Run("murmur32 hashing, legacy", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HashKeys = true
		globalConf.HashKeyFunction = ""
		config.SetGlobal(globalConf)

		LoadAPI(api)

		key := CreateSession()

		ts.Run(t, []test.TestCase{
			genTestCase("wrong", 403),
			genTestCase(key+"abc", 403),
			genTestCase(key, 200),
		}...)
	})

	t.Run("murmur32 hashing, json keys", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HashKeys = true
		globalConf.HashKeyFunction = "murmur32"
		config.SetGlobal(globalConf)

		LoadAPI(api)

		key := CreateSession()

		ts.Run(t, []test.TestCase{
			genTestCase("wrong", 403),
			// Should reject instead, just to show bug
			genTestCase(key+"abc", 200),
			genTestCase(key, 200),
		}...)
	})

	t.Run("murmur64 hashing", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HashKeys = true
		globalConf.HashKeyFunction = "murmur64"
		config.SetGlobal(globalConf)

		LoadAPI(api)

		key := CreateSession()

		ts.Run(t, []test.TestCase{
			genTestCase("wrong", 403),
			// New hashing fixes the bug
			genTestCase(key+"abc", 403),
			genTestCase(key, 200),
		}...)
	})
}

func TestSignatureValidation(t *testing.T) {
	defer ResetTestConfig()
	ts := StartTest()
	defer ts.Close()
	api := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			authTokenType: {
				ValidateSignature: true,
				UseParam:          true,
				ParamName:         "api_key",
				Signature: apidef.SignatureConfig{
					UseParam:         true,
					ParamName:        "sig",
					Secret:           "foobar",
					Algorithm:        "MasheryMD5",
					Header:           "Signature",
					AllowedClockSkew: 1,
				},
			},
		}
	})[0]

	LoadAPI(api)

	t.Run("Static signature", func(t *testing.T) {
		key := CreateSession()
		hasher := signature_validator.MasheryMd5sum{}
		validHash := hasher.Hash(key, "foobar", time.Now().Unix())

		validSigHeader := map[string]string{
			"authorization": key,
			"signature":     hex.EncodeToString(validHash),
		}

		invalidSigHeader := map[string]string{
			"authorization": key,
			"signature":     "junk",
		}

		emptySigHeader := map[string]string{
			"authorization": key,
		}
		storage.DisableRedis(true)
		ts.Run(t, []test.TestCase{
			{Headers: emptySigHeader, Code: http.StatusForbidden},
			{Headers: invalidSigHeader, Code: http.StatusForbidden},
			{Headers: validSigHeader, Code: http.StatusForbidden},
		}...)
		storage.DisableRedis(false)
		ts.Run(t, []test.TestCase{
			{Headers: emptySigHeader, Code: http.StatusUnauthorized},
			{Headers: invalidSigHeader, Code: http.StatusUnauthorized},
			{Headers: validSigHeader, Code: http.StatusOK},
		}...)
	})

	t.Run("Static signature in params", func(t *testing.T) {
		key := CreateSession()
		hasher := signature_validator.MasheryMd5sum{}
		validHash := hasher.Hash(key, "foobar", time.Now().Unix())

		emptySigPath := "?api_key=" + key
		invalidSigPath := emptySigPath + "&sig=junk"
		validSigPath := emptySigPath + "&sig=" + hex.EncodeToString(validHash)

		storage.DisableRedis(true)
		_, _ = ts.Run(t, []test.TestCase{
			{Path: emptySigPath, Code: http.StatusForbidden},
			{Path: invalidSigPath, Code: http.StatusForbidden},
			{Path: validSigPath, Code: http.StatusForbidden},
		}...)
		storage.DisableRedis(false)
		_, _ = ts.Run(t, []test.TestCase{
			{Path: emptySigPath, Code: http.StatusUnauthorized},
			{Path: invalidSigPath, Code: http.StatusUnauthorized},
			{Path: validSigPath, Code: http.StatusOK},
		}...)
	})

	t.Run("Dynamic signature", func(t *testing.T) {
		authConfig := api.AuthConfigs[authTokenType]
		authConfig.Signature.Secret = "$tyk_meta.signature_secret"
		api.AuthConfigs[authTokenType] = authConfig
		LoadAPI(api)

		key := CreateSession(func(s *user.SessionState) {
			s.MetaData = map[string]interface{}{
				"signature_secret": "foobar",
			}
		})

		hasher := signature_validator.MasheryMd5sum{}
		validHash := hasher.Hash(key, "foobar", time.Now().Unix())

		validSigHeader := map[string]string{
			"authorization": key,
			"signature":     hex.EncodeToString(validHash),
		}

		invalidSigHeader := map[string]string{
			"authorization": key,
			"signature":     "junk",
		}
		storage.DisableRedis(true)
		ts.Run(t, []test.TestCase{
			{Headers: invalidSigHeader, Code: http.StatusForbidden},
			{Headers: validSigHeader, Code: http.StatusForbidden},
		}...)
		storage.DisableRedis(false)
		ts.Run(t, []test.TestCase{
			{Headers: invalidSigHeader, Code: http.StatusUnauthorized},
			{Headers: validSigHeader, Code: http.StatusOK},
		}...)
	})

	t.Run("Dynamic signature with custom key", func(t *testing.T) {
		authConfig := api.AuthConfigs[authTokenType]
		authConfig.Signature.Secret = "$tyk_meta.signature_secret"
		api.AuthConfigs[authTokenType] = authConfig
		LoadAPI(api)

		customKey := "c8zj99aze7hdvtaqh4qvcck7"
		secret := "foobar"

		session := CreateStandardSession()
		session.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}
		session.MetaData = map[string]interface{}{
			"signature_secret": secret,
		}

		client := GetTLSClient(nil, nil)
		_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/keys/" + customKey,
			Data: session, Client: client, Code: http.StatusOK})

		hasher := signature_validator.MasheryMd5sum{}

		// First request is for raw key scenarios, signature is based on this key:
		validHash := hasher.Hash(customKey, secret, time.Now().Unix())
		validSigHeader := map[string]string{
			"authorization": customKey,
			"signature":     hex.EncodeToString(validHash),
		}

		// Second request uses token (org ID + key) and token-based signature:
		token, err := storage.GenerateToken("default", customKey, "murmur64")
		if err != nil {
			t.Fatal(err)
		}
		validHash2 := hasher.Hash(token, secret, time.Now().Unix())
		validSigHeader2 := map[string]string{
			"authorization": token,
			"signature":     hex.EncodeToString(validHash2),
		}

		// Third request uses token (org ID + key) and raw key based signature:
		validSigHeader3 := map[string]string{
			"authorization": token,
			"signature":     hex.EncodeToString(validHash),
		}

		// Fourth request uses raw key and token-based signature:
		validSigHeader4 := map[string]string{
			"authorization": customKey,
			"signature":     hex.EncodeToString(validHash2),
		}

		invalidSigHeader := map[string]string{
			"authorization": customKey,
			"signature":     "junk",
		}
		storage.DisableRedis(true)
		ts.Run(t, []test.TestCase{
			{Headers: invalidSigHeader, Code: http.StatusForbidden},
			{Headers: validSigHeader, Code: http.StatusForbidden},
			{Headers: validSigHeader2, Code: http.StatusForbidden},
			{Headers: validSigHeader3, Code: http.StatusForbidden},
			{Headers: validSigHeader4, Code: http.StatusForbidden},
		}...)
		storage.DisableRedis(false)
		ts.Run(t, []test.TestCase{
			{Headers: invalidSigHeader, Code: http.StatusUnauthorized},
			{Headers: validSigHeader, Code: http.StatusOK},
			{Headers: validSigHeader2, Code: http.StatusOK},
			{Headers: validSigHeader3, Code: http.StatusOK},
			{Headers: validSigHeader4, Code: http.StatusOK},
		}...)
	})
}

func createAuthKeyAuthSession(isBench bool) *user.SessionState {
	session := new(user.SessionState)
	// essentially non-throttled
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
		session.QuotaRemaining = 10
		session.QuotaMax = 10
	}
	session.AccessRights = map[string]user.AccessDefinition{"31": {APIName: "Tyk Auth Key Test", APIID: "31", Versions: []string{"default"}}}
	return session
}

func getAuthKeyChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec, nil)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{Spec: spec, Proxy: proxy}
	chain := alice.New(mwList(
		&IPWhiteListMiddleware{baseMid},
		&IPBlackListMiddleware{BaseMiddleware: baseMid},
		&AuthKey{baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
		&KeyExpired{baseMid},
		&AccessRightsCheck{baseMid},
		&RateLimitAndQuotaCheck{baseMid},
	)...).Then(proxyHandler)
	return chain
}

func testPrepareAuthKeySession(apiDef string, isBench bool) (string, *APISpec) {
	spec := LoadSampleAPI(apiDef)

	session := createAuthKeyAuthSession(isBench)
	customToken := ""
	if isBench {
		customToken = uuid.New()
	} else {
		customToken = "54321111"
	}
	// AuthKey sessions are stored by {token}
	GlobalSessionManager.UpdateSession(customToken, session, 60, false)
	return customToken, spec
}

func TestBearerTokenAuthKeySession(t *testing.T) {
	customToken, spec := testPrepareAuthKeySession(authKeyDef, false)

	recorder := httptest.NewRecorder()
	req := TestReq(t, "GET", "/auth_key_test/", nil)

	req.Header.Set("authorization", "Bearer "+customToken)

	chain := getAuthKeyChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}
}

func BenchmarkBearerTokenAuthKeySession(b *testing.B) {
	b.ReportAllocs()

	customToken, spec := testPrepareAuthKeySession(authKeyDef, true)

	recorder := httptest.NewRecorder()
	req := TestReq(b, "GET", "/auth_key_test/", nil)

	req.Header.Set("authorization", "Bearer "+customToken)

	chain := getAuthKeyChain(spec)

	for i := 0; i < b.N; i++ {
		chain.ServeHTTP(recorder, req)
		if recorder.Code != 200 {
			b.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
			b.Error(recorder.Body.String())
		}
	}
}

const authKeyDef = `{
	"api_id": "31",
	"org_id": "default",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/auth_key_test/",
		"target_url": "` + TestHttpAny + `"
	}
}`

func TestMultiAuthBackwardsCompatibleSession(t *testing.T) {
	customToken, spec := testPrepareAuthKeySession(multiAuthBackwardsCompatible, false)

	recorder := httptest.NewRecorder()
	req := TestReq(t, "GET", fmt.Sprintf("/auth_key_test/?token=%s", customToken), nil)

	chain := getAuthKeyChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}
}

func BenchmarkMultiAuthBackwardsCompatibleSession(b *testing.B) {
	b.ReportAllocs()

	customToken, spec := testPrepareAuthKeySession(multiAuthBackwardsCompatible, true)

	recorder := httptest.NewRecorder()
	req := TestReq(b, "GET", fmt.Sprintf("/auth_key_test/?token=%s", customToken), nil)

	chain := getAuthKeyChain(spec)

	for i := 0; i < b.N; i++ {
		chain.ServeHTTP(recorder, req)
		if recorder.Code != 200 {
			b.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
			b.Error(recorder.Body.String())
		}
	}
}

const multiAuthBackwardsCompatible = `{
	"api_id": "31",
	"org_id": "default",
	"auth": {
		"auth_header_name": "token",
		"use_param": true
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/auth_key_test/",
		"target_url": "` + TestHttpAny + `"
	}
}`

func TestMultiAuthSession(t *testing.T) {
	spec := LoadSampleAPI(multiAuthDef)
	session := createAuthKeyAuthSession(false)
	customToken := "54321111"
	// AuthKey sessions are stored by {token}
	GlobalSessionManager.UpdateSession(customToken, session, 60, false)

	// Set the url param
	recorder := httptest.NewRecorder()
	req := TestReq(t, "GET", fmt.Sprintf("/auth_key_test/?token=%s", customToken), nil)

	chain := getAuthKeyChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("First request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}

	// Set the header
	recorder = httptest.NewRecorder()
	req = TestReq(t, "GET", "/auth_key_test/?token=", nil)
	req.Header.Set("authorization", customToken)

	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Second request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}

	// Set the cookie
	recorder = httptest.NewRecorder()
	req = TestReq(t, "GET", "/auth_key_test/?token=", nil)
	req.AddCookie(&http.Cookie{Name: "oreo", Value: customToken})

	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Third request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}

	// No header, param or cookie
	recorder = httptest.NewRecorder()
	req = TestReq(t, "GET", "/auth_key_test/", nil)

	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request returned 200 code, should NOT have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}
}

const multiAuthDef = `{
	"api_id": "31",
	"org_id": "default",
	"auth": {
		"auth_header_name": "authorization",
		"param_name": "token",
		"cookie_name": "oreo"
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/auth_key_test/",
		"target_url": "` + TestHttpAny + `"
	}
}`

func TestStripBearer(t *testing.T) {
	var bearerTests = []struct {
		in  string
		out string
	}{
		{"Bearer abc", "abc"},
		{"bearer abc", "abc"},
		{"bEaReR abc", "abc"},
		{"Bearer: abc", "Bearer: abc"}, // invalid
		{"Basic abc", "Basic abc"},
		{"abc", "abc"},
	}

	for _, tt := range bearerTests {
		t.Run(tt.in, func(t *testing.T) {
			out := stripBearer(tt.in)
			if out != tt.out {
				t.Errorf("got %q, want %q", out, tt.out)
			}
		})
	}
}

func BenchmarkStripBearer(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = stripBearer("Bearer abcdefghijklmnopqrstuvwxyz12345678910")
	}
}
