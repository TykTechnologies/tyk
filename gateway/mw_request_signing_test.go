package gateway

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/certs"

	"github.com/stretchr/testify/assert"

	"github.com/justinas/alice"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

var algoList = [4]string{"hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512"}

func (ts *Test) getMiddlewareChain(spec *APISpec) http.Handler {

	remote, _ := url.Parse(TestHttpAny)
	proxy := ts.Gw.TykNewSingleHostReverseProxy(remote, spec, logrus.New().WithFields(logrus.Fields{}))
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{Spec: spec, Proxy: proxy, Gw: ts.Gw}
	chain := alice.New(ts.Gw.mwList(
		&IPWhiteListMiddleware{baseMid},
		&IPBlackListMiddleware{BaseMiddleware: baseMid},
		&RequestSigning{BaseMiddleware: baseMid},
		&HTTPSignatureValidationMiddleware{BaseMiddleware: baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
	)...).Then(proxyHandler)
	return chain
}

func (ts *Test) generateSession(algo, data string) string {
	sessionKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		if strings.HasPrefix(algo, "rsa") {
			s.RSACertificateId = data
			s.EnableHTTPSignatureValidation = true
		} else {
			s.HmacSecret = data
			s.HMACEnabled = true
		}
	})

	return sessionKey
}

func (ts *Test) generateSpec(algo string, data string, sessionKey string, headerList []string) (specs []*APISpec) {
	return ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.UseKeylessAccess = true
		spec.EnableSignatureChecking = true
		spec.RequestSigning.IsEnabled = true
		spec.RequestSigning.KeyId = sessionKey
		spec.HmacAllowedClockSkew = 5000

		if strings.HasPrefix(algo, "rsa") {
			spec.RequestSigning.CertificateId = data
		} else {
			spec.RequestSigning.Secret = data
		}
		spec.RequestSigning.Algorithm = algo
		if headerList != nil {
			spec.RequestSigning.HeaderList = headerList
		}

	})
}

func TestHMACRequestSigning(t *testing.T) {

	secret := "9879879878787878"

	for _, algo := range algoList {
		name := "Test with " + algo
		t.Run(name, func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			sessionKey := ts.generateSession(algo, secret)
			specs := ts.generateSpec(algo, secret, sessionKey, nil)

			req := TestReq(t, "get", "/test/get", nil)
			recorder := httptest.NewRecorder()
			chain := ts.getMiddlewareChain(specs[0])
			chain.ServeHTTP(recorder, req)

			if recorder.Code != 200 {
				t.Error("HMAC request signing failed with error:", recorder.Body.String())
			}
		})
	}

	t.Run("Empty secret", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		algo := "hmac-sha256"
		secret := ""

		sessionKey := ts.generateSession(algo, secret)
		specs := ts.generateSpec(algo, secret, sessionKey, nil)

		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])

		req := TestReq(t, "get", "/test/get", nil)
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 500 {
			t.Error("Expected status code 500 got ", recorder.Code)
		}
	})

	t.Run("Invalid secret", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		algo := "hmac-sha256"
		secret := "12345"

		sessionKey := ts.generateSession(algo, secret)
		specs := ts.generateSpec(algo, "789", sessionKey, nil)

		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])

		req := TestReq(t, "get", "/test/get", nil)
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 400 {
			t.Error("Expected status code 400 got ", recorder.Code)
		}
	})

	t.Run("Valid Custom headerList", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		algo := "hmac-sha1"
		headerList := []string{"foo", "date"}

		sessionKey := ts.generateSession(algo, secret)
		specs := ts.generateSpec(algo, secret, sessionKey, headerList)

		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])

		req := TestReq(t, "get", "/test/get", nil)
		refDate := "Mon, 02 Jan 2006 15:04:05 MST"
		tim := time.Now().Format(refDate)
		req.Header.Add("foo", "bar")
		req.Header.Add("date", tim)
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("HMAC request signing failed with error:", recorder.Body.String())
		}
	})

	t.Run("Invalid Custom headerList", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		algo := "hmac-sha1"
		headerList := []string{"foo"}

		sessionKey := ts.generateSession(algo, secret)
		specs := ts.generateSpec(algo, secret, sessionKey, headerList)

		req := TestReq(t, "get", "/test/get", nil)
		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("HMAC request signing failed with error:", recorder.Body.String())
		}
	})

	t.Run("Invalid algorithm", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		algo := "hmac-123"
		sessionKey := ts.generateSession(algo, secret)
		specs := ts.generateSpec(algo, secret, sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 500 {
			t.Error("Expected status code 500 got ", recorder.Code)
		}
	})

	t.Run("Invalid Date field", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		algo := "hmac-sha1"
		sessionKey := ts.generateSession(algo, secret)
		specs := ts.generateSpec(algo, secret, sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		// invalid date
		req.Header.Add("date", "Mon, 02 Jan 2006 15:04:05 GMT")

		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 400 {
			t.Error("Expected status code 400 got ", recorder.Code)
		}
	})

	t.Run("Custom Signature header", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		algo := "hmac-sha256"

		sessionKey := ts.generateSession(algo, secret)
		specs := ts.generateSpec(algo, secret, sessionKey, nil)
		api := specs[0]

		api.AuthConfigs = make(map[string]apidef.AuthConfig)
		api.AuthConfigs["hmac"] = apidef.AuthConfig{
			AuthHeaderName: "something",
		}

		api.RequestSigning.SignatureHeader = "something"

		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(api)

		req := TestReq(t, "get", "/test/get", nil)
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("HMAC request signing failed with error:", recorder.Body.String())
		}
	})
}

func TestRSARequestSigning(t *testing.T) {

	ts := StartTest(nil)
	defer ts.Close()

	_, _, combinedPem, cert := certs.GenServerCertificate()
	privCertId, _ := ts.Gw.CertificateManager.Add(combinedPem, "")
	defer ts.Gw.CertificateManager.Delete(privCertId, "")

	x509Cert, _ := x509.ParseCertificate(cert.Certificate[0])
	pubDer, _ := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	pubCertId, _ := ts.Gw.CertificateManager.Add(pubPem, "")
	defer ts.Gw.CertificateManager.Delete(pubCertId, "")

	name := "Test with rsa-sha256"
	t.Run(name, func(t *testing.T) {
		algo := "rsa-sha256"
		sessionKey := ts.generateSession(algo, pubCertId)
		specs := ts.generateSpec(algo, privCertId, sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("RSA request signing failed with error:", recorder.Body.String())
		}
	})

	t.Run("Invalid certificate id", func(t *testing.T) {
		algo := "rsa-sha256"
		sessionKey := ts.generateSession(algo, pubCertId)
		specs := ts.generateSpec(algo, "12345", sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 500 {
			t.Error("Expected status code 500 got ", recorder.Code)
		}
	})

	t.Run("empty certificate id", func(t *testing.T) {
		algo := "rsa-sha256"
		sessionKey := ts.generateSession(algo, pubCertId)
		specs := ts.generateSpec(algo, "", sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 500 {
			t.Error("Expected status code 500 got ", recorder.Code)
		}
	})

	t.Run("Invalid algorithm", func(t *testing.T) {
		algo := "rsa-123"
		sessionKey := ts.generateSession(algo, pubCertId)
		specs := ts.generateSpec(algo, privCertId, sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 500 {
			t.Error("Expected status code 500 got ", recorder.Code)
		}
	})

	t.Run("Invalid Date field", func(t *testing.T) {
		algo := "rsa-sha256"
		sessionKey := ts.generateSession(algo, pubCertId)
		specs := ts.generateSpec(algo, privCertId, sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		req.Header.Add("date", "Mon, 02 Jan 2006 15:04:05 GMT")
		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 400 {
			t.Error("Expected status code 400 got ", recorder.Code)
		}
	})

	t.Run("Custom headerList", func(t *testing.T) {
		algo := "rsa-sha256"
		headerList := []string{"foo", "date"}

		sessionKey := ts.generateSession(algo, pubCertId)
		specs := ts.generateSpec(algo, privCertId, sessionKey, headerList)

		req := TestReq(t, "get", "/test/get", nil)

		refDate := "Mon, 02 Jan 2006 15:04:05 MST"
		tim := time.Now().Format(refDate)
		req.Header.Add("foo", "bar")
		req.Header.Add("date", tim)

		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("RSA request signing failed with error ", recorder.Body.String())
		}
	})

	t.Run("Non-existing Custom headers", func(t *testing.T) {
		algo := "rsa-sha256"
		headerList := []string{"foo"}

		sessionKey := ts.generateSession(algo, pubCertId)
		specs := ts.generateSpec(algo, privCertId, sessionKey, headerList)

		req := TestReq(t, "get", "/test/get", nil)

		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("RSA request signing failed with error ", recorder.Body.String())
		}
	})

	t.Run("Custom Signature header", func(t *testing.T) {
		algo := "rsa-sha256"

		sessionKey := ts.generateSession(algo, pubCertId)
		specs := ts.generateSpec(algo, privCertId, sessionKey, nil)

		api := specs[0]
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
		api.AuthConfigs["hmac"] = apidef.AuthConfig{
			AuthHeaderName: "something",
		}

		api.RequestSigning.SignatureHeader = "something"

		req := TestReq(t, "get", "/test/get", nil)

		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("RSA request signing failed with error ", recorder.Body.String())
		}
	})
}

func TestAPISpec_StripListenPath(t *testing.T) {
	algo := "hmac-sha256"
	secret := "12345"

	t.Run("Off", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		sessionKey := ts.generateSession(algo, secret)
		specs := ts.generateSpec(algo, secret, sessionKey, nil)
		req := TestReq(t, "get", "/test/get", nil)

		recorder := httptest.NewRecorder()
		chain := ts.getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("Expected status code 200 got ", recorder.Code)
		}
	})

	t.Run("On", func(t *testing.T) {
		test.Flaky(t) // TODO: TT-5255

		ts := StartTest(nil)
		defer ts.Close()

		sessionKey := ts.generateSession(algo, secret)
		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.APIID = "protected"
				spec.Proxy.ListenPath = "/protected"
				spec.EnableSignatureChecking = true
				spec.UseKeylessAccess = false
				spec.Proxy.StripListenPath = true
			},
			func(spec *APISpec) {
				spec.APIID = "trailingSlash"
				spec.Proxy.ListenPath = "/trailingSlash/"
				spec.Proxy.StripListenPath = true
				spec.RequestSigning.IsEnabled = true
				spec.RequestSigning.Secret = secret
				spec.RequestSigning.KeyId = sessionKey
				spec.RequestSigning.Algorithm = algo
				spec.Proxy.TargetURL = ts.URL
			},
			func(spec *APISpec) {
				spec.APIID = "withoutTrailingSlash"
				spec.Proxy.ListenPath = "/withoutTrailingSlash"
				spec.Proxy.StripListenPath = true
				spec.RequestSigning.IsEnabled = true
				spec.RequestSigning.Secret = secret
				spec.RequestSigning.KeyId = sessionKey
				spec.RequestSigning.Algorithm = algo
				spec.Proxy.TargetURL = ts.URL
			},
		)

		ts.Run(t, []test.TestCase{
			{Path: "/trailingSlash/protected/get", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/withoutTrailingSlash/protected/get", Method: http.MethodGet, Code: http.StatusOK},
		}...)
	})
}

func TestWithURLRewrite(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	algo := "hmac-sha256"
	secret := "12345"

	sessionKey := CreateSession(ts.Gw, func(session *user.SessionState) {
		session.EnableHTTPSignatureValidation = true
		session.HmacSecret = secret
	})

	t.Run("looping", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "protected"
			spec.Proxy.ListenPath = "/protected"
			spec.EnableSignatureChecking = true
			spec.UseKeylessAccess = false
		}, func(spec *APISpec) {
			spec.APIID = "test"
			spec.Proxy.ListenPath = "/test"
			spec.Proxy.StripListenPath = true
			spec.RequestSigning.IsEnabled = true
			spec.RequestSigning.Secret = secret
			spec.RequestSigning.KeyId = sessionKey
			spec.RequestSigning.Algorithm = algo

			version := spec.VersionData.Versions["v1"]
			version.UseExtendedPaths = true
			version.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{
				{
					Path:         "/get",
					Method:       "GET",
					MatchPattern: "/get",
					RewriteTo:    "tyk://protected/get",
				},
				{
					Path:         "/self",
					Method:       "GET",
					MatchPattern: "/self",
					RewriteTo:    "tyk://protected/test/get",
				},
			}

			spec.VersionData.Versions["v1"] = version
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test/get", Method: http.MethodGet, Code: http.StatusOK},
			// ensure listen path is not stripped in case url rewrite
			{Path: "/test/self", Method: http.MethodGet, Code: http.StatusOK},
		}...)
	})

	t.Run("external", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "protected"
			spec.Proxy.ListenPath = "/protected"
			spec.EnableSignatureChecking = true
		}, func(spec *APISpec) {
			spec.APIID = "test"
			spec.Proxy.ListenPath = "/test/"
			spec.Proxy.StripListenPath = true
			spec.RequestSigning.IsEnabled = true
			spec.RequestSigning.Secret = secret
			spec.RequestSigning.KeyId = sessionKey
			spec.RequestSigning.Algorithm = algo

			version := spec.VersionData.Versions["v1"]
			version.UseExtendedPaths = true
			version.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{
				{
					Path:         "get",
					Method:       "GET",
					MatchPattern: "get",
					RewriteTo:    ts.URL + "/protected/get",
				},
				{
					Path:         "self",
					Method:       "GET",
					MatchPattern: "self",
					RewriteTo:    ts.URL + "/protected/test/get",
				},
			}

			spec.VersionData.Versions["v1"] = version
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test/get", Method: http.MethodGet, Code: http.StatusOK},
			// ensure listen path is not stripped in case url rewrite
			{Path: "/test/self", Method: http.MethodGet, Code: http.StatusOK},
		}...)
	})

}

func TestRequestSigning_getRequestPath(t *testing.T) {
	api := BuildAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test/"
		spec.Proxy.StripListenPath = false
	})[0]

	ts := StartTest(nil)
	defer ts.Close()

	rs := RequestSigning{BaseMiddleware{Spec: api, Gw: ts.Gw}}

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/test/get?param1=value1", nil)

	t.Run("StripListenPath=true", func(t *testing.T) {
		api.Proxy.StripListenPath = true
		assert.Equal(t, "/get?param1=value1", rs.getRequestPath(req))

		t.Run("path is empty", func(t *testing.T) {
			reqWithEmptyPath, _ := http.NewRequest(http.MethodGet, "http://example.com/test/", nil)
			assert.Equal(t, "/", rs.getRequestPath(reqWithEmptyPath))
		})

		api.Proxy.StripListenPath = false
	})

	t.Run("URL rewrite", func(t *testing.T) {
		rewrittenURL := &url.URL{Path: "/test/rewritten", RawQuery: "param1=value1"}
		ctxSetURLRewriteTarget(req, rewrittenURL)
		assert.Equal(t, "/test/rewritten?param1=value1", rs.getRequestPath(req))
		ctxSetURLRewriteTarget(req, nil)
	})
}
