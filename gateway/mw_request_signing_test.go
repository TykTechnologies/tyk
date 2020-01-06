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

	"github.com/justinas/alice"

	"github.com/TykTechnologies/tyk/user"
)

var algoList = [4]string{"hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512"}

func getMiddlewareChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(TestHttpAny)
	proxy := TykNewSingleHostReverseProxy(remote, spec, nil)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{Spec: spec, Proxy: proxy}
	chain := alice.New(mwList(
		&IPWhiteListMiddleware{baseMid},
		&IPBlackListMiddleware{BaseMiddleware: baseMid},
		&RequestSigning{BaseMiddleware: baseMid},
		&HTTPSignatureValidationMiddleware{BaseMiddleware: baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
	)...).Then(proxyHandler)
	return chain
}

func generateSession(algo, data string) string {
	sessionKey := CreateSession(func(s *user.SessionState) {
		if strings.HasPrefix(algo, "rsa") {
			s.RSACertificateId = data
			s.EnableHTTPSignatureValidation = true
		} else {
			s.HmacSecret = data
			s.HMACEnabled = true
		}

		s.AccessRights = map[string]user.AccessDefinition{"protected": {APIID: "protected", Versions: []string{"v1"}}}
	})

	return sessionKey
}

func generateSpec(algo string, data string, sessionKey string, headerList []string) (specs []*APISpec) {
	return BuildAndLoadAPI(func(spec *APISpec) {
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
	ts := StartTest()
	defer ts.Close()
	secret := "9879879878787878"

	for _, algo := range algoList {
		name := "Test with " + algo
		t.Run(name, func(t *testing.T) {
			sessionKey := generateSession(algo, secret)
			specs := generateSpec(algo, secret, sessionKey, nil)

			req := TestReq(t, "get", "/test/get", nil)
			recorder := httptest.NewRecorder()
			chain := getMiddlewareChain(specs[0])
			chain.ServeHTTP(recorder, req)

			if recorder.Code != 200 {
				t.Error("HMAC request signing failed with error:", recorder.Body.String())
			}
		})
	}

	t.Run("Valid Custom headerList", func(t *testing.T) {
		algo := "hmac-sha1"
		headerList := []string{"foo", "date"}

		sessionKey := generateSession(algo, secret)
		specs := generateSpec(algo, secret, sessionKey, headerList)

		recorder := httptest.NewRecorder()
		chain := getMiddlewareChain(specs[0])

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
		algo := "hmac-sha1"
		headerList := []string{"foo"}

		sessionKey := generateSession(algo, secret)
		specs := generateSpec(algo, secret, sessionKey, headerList)

		req := TestReq(t, "get", "/test/get", nil)
		recorder := httptest.NewRecorder()
		chain := getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("HMAC request signing failed with error:", recorder.Body.String())
		}
	})

	t.Run("Invalid algorithm", func(t *testing.T) {
		algo := "hmac-123"
		sessionKey := generateSession(algo, secret)
		specs := generateSpec(algo, secret, sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		recorder := httptest.NewRecorder()
		chain := getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 500 {
			t.Error("Expected status code 500 got ", recorder.Code)
		}
	})

	t.Run("Invalid Date field", func(t *testing.T) {
		algo := "hmac-sha1"
		sessionKey := generateSession(algo, secret)
		specs := generateSpec(algo, secret, sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		// invalid date
		req.Header.Add("date", "Mon, 02 Jan 2006 15:04:05 GMT")

		recorder := httptest.NewRecorder()
		chain := getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 400 {
			t.Error("Expected status code 400 got ", recorder.Code)
		}
	})
}

func TestRSARequestSigning(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	_, _, combinedPem, cert := genServerCertificate()
	privCertId, _ := CertificateManager.Add(combinedPem, "")
	defer CertificateManager.Delete(privCertId)

	x509Cert, _ := x509.ParseCertificate(cert.Certificate[0])
	pubDer, _ := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	pubCertId, _ := CertificateManager.Add(pubPem, "")
	defer CertificateManager.Delete(pubCertId)

	name := "Test with rsa-sha256"
	t.Run(name, func(t *testing.T) {
		algo := "rsa-sha256"
		sessionKey := generateSession(algo, pubCertId)
		specs := generateSpec(algo, privCertId, sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		recorder := httptest.NewRecorder()
		chain := getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("RSA request signing failed with error:", recorder.Body.String())
		}
	})

	t.Run("Invalid algorithm", func(t *testing.T) {
		algo := "rsa-123"
		sessionKey := generateSession(algo, pubCertId)
		specs := generateSpec(algo, privCertId, sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		recorder := httptest.NewRecorder()
		chain := getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 500 {
			t.Error("Expected status code 500 got ", recorder.Code)
		}
	})

	t.Run("Invalid Date field", func(t *testing.T) {
		algo := "rsa-sha256"
		sessionKey := generateSession(algo, pubCertId)
		specs := generateSpec(algo, privCertId, sessionKey, nil)

		req := TestReq(t, "get", "/test/get", nil)
		req.Header.Add("date", "Mon, 02 Jan 2006 15:04:05 GMT")
		recorder := httptest.NewRecorder()
		chain := getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 400 {
			t.Error("Expected status code 400 got ", recorder.Code)
		}
	})

	t.Run("Custom headerList", func(t *testing.T) {
		algo := "rsa-sha256"
		headerList := []string{"foo", "date"}

		sessionKey := generateSession(algo, pubCertId)
		specs := generateSpec(algo, privCertId, sessionKey, headerList)

		req := TestReq(t, "get", "/test/get", nil)

		refDate := "Mon, 02 Jan 2006 15:04:05 MST"
		tim := time.Now().Format(refDate)
		req.Header.Add("foo", "bar")
		req.Header.Add("date", tim)

		recorder := httptest.NewRecorder()
		chain := getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("RSA request signing failed with error ", recorder.Body.String())
		}
	})

	t.Run("Non-existing Custom headers", func(t *testing.T) {
		algo := "rsa-sha256"
		headerList := []string{"foo"}

		sessionKey := generateSession(algo, pubCertId)
		specs := generateSpec(algo, privCertId, sessionKey, headerList)

		req := TestReq(t, "get", "/test/get", nil)

		recorder := httptest.NewRecorder()
		chain := getMiddlewareChain(specs[0])
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Error("RSA request signing failed with error ", recorder.Body.String())
		}
	})
}
