package gateway

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
)

type TestAuth struct {
	apidef.AuthConfig
	HeaderKey  string
	QueryParam string
}

func testPrepareStripAuthStripFromHeaders() ([]string, []TestAuth) {
	testCases := []TestAuth{
		{AuthConfig: apidef.AuthConfig{AuthHeaderName: "Authorization"}, HeaderKey: "Authorization"},
		{AuthConfig: apidef.AuthConfig{AuthHeaderName: ""}, HeaderKey: "Authorization"},
		{AuthConfig: apidef.AuthConfig{AuthHeaderName: "MyAuth"}, HeaderKey: "MyAuth"},
	}

	miscHeaders := []string{
		"ABC",
		"Def",
		"GHI",
		"Authorisation",
	}

	return miscHeaders, testCases
}

func TestStripAuth_stripFromHeaders(t *testing.T) {
	miscHeaders, testCases := testPrepareStripAuthStripFromHeaders()

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("stripping %+v", tc), func(t *testing.T) {

			sa := StripAuth{}
			sa.Spec = &APISpec{APIDefinition: &apidef.APIDefinition{}}

			req, err := http.NewRequest("GET", "http://example.com", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Add(tc.HeaderKey, randStringBytes(5))

			if req.Header.Get(tc.HeaderKey) == "" {
				t.Fatal("headerkey not in headers to start with", tc.HeaderKey)
			}

			for _, h := range miscHeaders {
				req.Header.Add(h, randStringBytes(5))
			}

			sa.stripFromHeaders(req, &tc.AuthConfig)

			if len(req.Header) != len(miscHeaders) {
				t.Logf("miscHeaders %d %+v\n", len(miscHeaders), miscHeaders)
				t.Logf("reqHeader %d %+v\n", len(req.Header), req.Header)

				t.Error("unexpected number of headers")
			}

			if req.Header.Get(tc.HeaderKey) != "" {
				t.Error("stripFromHeaders didn't strip", tc.HeaderKey)
			}
		})
	}

	t.Run("strip authorization from cookie", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://example.com", nil)
		if err != nil {
			t.Fatal(err)
		}
		sa := StripAuth{}
		sa.Spec = &APISpec{APIDefinition: &apidef.APIDefinition{}}

		key := "Authorization"
		stripFromCookieTest(t, req, key, sa, "Authorization=AUTHORIZATION", "")
		stripFromCookieTest(t, req, key, sa, "Authorization=AUTHORIZATION;Dummy=DUMMY", "Dummy=DUMMY")
		stripFromCookieTest(t, req, key, sa, "Dummy=DUMMY;Authorization=AUTHORIZATION", "Dummy=DUMMY")
		stripFromCookieTest(t, req, key, sa, "Dummy=DUMMY;Authorization=AUTHORIZATION;Dummy2=DUMMY2", "Dummy=DUMMY;Dummy2=DUMMY2")

		key = "NonDefaultName"
		sa.Spec.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {CookieName: key},
		}
		stripFromCookieTest(t, req, key, sa, "Dummy=DUMMY;NonDefaultName=AUTHORIZATION;Dummy2=DUMMY2", "Dummy=DUMMY;Dummy2=DUMMY2")
		// whitespace between cookies
		stripFromCookieTest(t, req, key, sa, "Dummy=DUMMY; NonDefaultName=AUTHORIZATION; Dummy2=DUMMY2", "Dummy=DUMMY; Dummy2=DUMMY2")
	})
}

func stripFromCookieTest(t *testing.T, req *http.Request, key string, sa StripAuth, value string, expected string) {
	req.Header.Set("Cookie", value)
	config := sa.Spec.AuthConfigs[apidef.AuthTokenType]
	sa.stripFromHeaders(req, &config)

	actual := req.Header.Get("Cookie")

	if expected != actual {
		t.Fatalf("Expected %s, actual %s", expected, actual)
	}
}

func BenchmarkStripAuth_stripFromHeaders(b *testing.B) {
	b.ReportAllocs()

	miscHeaders, testCases := testPrepareStripAuthStripFromHeaders()

	for i := 0; i < b.N; i++ {
		for _, tc := range testCases {
			sa := StripAuth{}
			sa.Spec = &APISpec{APIDefinition: &apidef.APIDefinition{}}

			req, err := http.NewRequest("GET", "http://example.com", nil)
			if err != nil {
				b.Fatal(err)
			}

			req.Header.Add(tc.HeaderKey, randStringBytes(5))

			if req.Header.Get(tc.HeaderKey) == "" {
				b.Fatal("headerkey not in headers to start with", tc.HeaderKey)
			}

			for _, h := range miscHeaders {
				req.Header.Add(h, randStringBytes(5))
			}

			sa.stripFromHeaders(req, &tc.AuthConfig)
		}
	}
}

func testPrepareStripAuthStripFromParams() ([]string, []TestAuth) {
	testCases := []TestAuth{
		// ParamName set, use it
		{AuthConfig: apidef.AuthConfig{UseParam: true, ParamName: "password1"}, QueryParam: "password1"},
		// ParamName not set, use AuthHeaderName
		{AuthConfig: apidef.AuthConfig{UseParam: true, ParamName: "", AuthHeaderName: "auth1"}, QueryParam: "auth1"},
		// ParamName takes precedence over AuthHeaderName
		{AuthConfig: apidef.AuthConfig{UseParam: true, ParamName: "auth2", AuthHeaderName: "auth3"}, QueryParam: "auth2"},
		// Both not set, use Authorization
		{AuthConfig: apidef.AuthConfig{UseParam: true, ParamName: "", AuthHeaderName: ""}, QueryParam: "Authorization"},
	}

	miscQueryStrings := []string{
		"ABC",
		"Def",
		"GHI",
		"Authorisation",
	}

	return miscQueryStrings, testCases
}

func TestStripAuth_stripFromParams(t *testing.T) {
	miscQueryStrings, testCases := testPrepareStripAuthStripFromParams()

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("stripping %s", tc.QueryParam), func(t *testing.T) {

			sa := StripAuth{}
			sa.Spec = &APISpec{APIDefinition: &apidef.APIDefinition{}}

			rawUrl := "http://example.com/abc"

			req, err := http.NewRequest("GET", rawUrl, nil)
			if err != nil {
				t.Fatal(err)
			}

			newQs := url.Values{}
			for _, qs := range miscQueryStrings {
				newQs.Add(qs, randStringBytes(5))
			}
			newQs.Add(tc.QueryParam, randStringBytes(10))

			req.URL.RawQuery = newQs.Encode()

			t.Logf("PARAM: %+v\n", req.URL.Query())

			if req.URL.Query().Get(tc.QueryParam) == "" {
				t.Fatal("params not present", tc.QueryParam)
			}

			sa.stripFromParams(req, &tc.AuthConfig)

			queryStringValues := req.URL.Query()

			if queryStringValues.Get(tc.QueryParam) != "" {
				t.Error("stripFromParams didn't strip ", sa.Spec.Auth.ParamName)
			}
		})
	}
}

func BenchmarkStripAuth_stripFromParams(b *testing.B) {
	b.ReportAllocs()

	miscQueryStrings, testCases := testPrepareStripAuthStripFromParams()

	for i := 0; i < b.N; i++ {
		for _, tc := range testCases {
			sa := StripAuth{}
			sa.Spec = &APISpec{APIDefinition: &apidef.APIDefinition{}}

			req, err := http.NewRequest("GET", "http://example.com/abc", nil)
			if err != nil {
				b.Fatal(err)
			}

			newQs := url.Values{}
			for _, qs := range miscQueryStrings {
				newQs.Add(qs, randStringBytes(5))
			}
			newQs.Add(tc.QueryParam, randStringBytes(10))

			req.URL.RawQuery = newQs.Encode()

			if req.URL.Query().Get(tc.QueryParam) == "" {
				b.Fatal("params not present", tc.QueryParam)
			}

			sa.stripFromParams(req, &tc.AuthConfig)
		}
	}
}
