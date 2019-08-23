package gateway

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

var algoList = [4]string{"hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512"}

func generateSession(algo, data string) string {
	sessionKey := CreateSession(func(s *user.SessionState) {
		if strings.HasPrefix(algo, "rsa") {
			s.RSACertificateId = data
			s.RSAEnabled = true
		} else {
			s.HmacSecret = data
			s.HMACEnabled = true
		}

		s.AccessRights = map[string]user.AccessDefinition{"protected": {APIID: "protected", Versions: []string{"v1"}}}
	})

	return sessionKey
}

func generateSpec(algo string, data string, sessionKey string, headerList []string) {
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "protected"
		spec.Name = "protected api"
		spec.Proxy.ListenPath = "/something"
		spec.EnableSignatureChecking = true
		spec.Auth.AuthHeaderName = "authorization"
		spec.HmacAllowedClockSkew = 5000
		spec.UseKeylessAccess = false
		spec.UseBasicAuth = false
		spec.UseOauth2 = false

		version := spec.VersionData.Versions["v1"]
		version.UseExtendedPaths = true
		spec.VersionData.Versions["v1"] = version
	}, func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.UseKeylessAccess = true
		spec.RequestSigning.IsEnabled = true
		spec.RequestSigning.KeyId = sessionKey

		if strings.HasPrefix(algo, "rsa") {
			spec.RequestSigning.CertificateId = data
		} else {
			spec.RequestSigning.Secret = data
		}
		spec.RequestSigning.Algorithm = algo
		if headerList != nil {
			spec.RequestSigning.HeaderList = headerList
		}

		version := spec.VersionData.Versions["v1"]
		json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "extended_paths": {
                    "url_rewrites": [{
                        "path": "/by_name",
                        "match_pattern": "/by_name(.*)",
                        "method": "GET",
                        "rewrite_to": "tyk://protected api/get"
                    }]
                }
            }`), &version)

		spec.VersionData.Versions["v1"] = version
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
			generateSpec(algo, secret, sessionKey, nil)

			ts.Run(t, []test.TestCase{
				{Path: "/test/by_name", Code: 200},
			}...)
		})
	}

	t.Run("Valid Custom headerList", func(t *testing.T) {
		algo := "hmac-sha1"
		headerList := []string{"foo", "date"}

		sessionKey := generateSession(algo, secret)
		generateSpec(algo, secret, sessionKey, headerList)

		refDate := "Mon, 02 Jan 2006 15:04:05 MST"
		tim := time.Now().Format(refDate)

		headers := map[string]string{"foo": "bar", "date": tim}

		ts.Run(t, []test.TestCase{
			{Path: "/test/by_name", Code: 200, Headers: headers},
		}...)
	})

	t.Run("Invalid Custom headerList", func(t *testing.T) {
		algo := "hmac-sha1"
		headerList := []string{"foo"}

		sessionKey := generateSession(algo, secret)
		generateSpec(algo, secret, sessionKey, headerList)

		ts.Run(t, []test.TestCase{
			{Path: "/test/by_name", Code: 200},
		}...)
	})

	t.Run("Invalid algorithm", func(t *testing.T) {
		algo := "hmac-123"
		sessionKey := generateSession(algo, secret)
		generateSpec(algo, secret, sessionKey, nil)

		ts.Run(t, []test.TestCase{
			{Path: "/test/by_name", Code: 500},
		}...)
	})

	t.Run("Invalid Date field", func(t *testing.T) {
		algo := "hmac-sha1"
		sessionKey := generateSession(algo, secret)
		generateSpec(algo, secret, sessionKey, nil)

		headers := map[string]string{"date": "Mon, 02 Jan 2006 15:04:05 GMT"}

		ts.Run(t, []test.TestCase{
			{Path: "/test/by_name", Headers: headers, Code: 400},
		}...)
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
		generateSpec(algo, privCertId, sessionKey, nil)

		ts.Run(t, []test.TestCase{
			{Path: "/test/by_name", Code: 200},
		}...)
	})

	t.Run("Invalid algorithm", func(t *testing.T) {
		algo := "rsa-123"
		sessionKey := generateSession(algo, pubCertId)
		generateSpec(algo, privCertId, sessionKey, nil)

		ts.Run(t, []test.TestCase{
			{Path: "/test/by_name", Code: 500},
		}...)
	})

	t.Run("Invalid Date field", func(t *testing.T) {
		algo := "rsa-sha256"
		sessionKey := generateSession(algo, pubCertId)
		generateSpec(algo, privCertId, sessionKey, nil)

		headers := map[string]string{"date": "Mon, 02 Jan 2006 15:04:05 GMT"}

		ts.Run(t, []test.TestCase{
			{Path: "/test/by_name", Headers: headers, Code: 400},
		}...)
	})

	t.Run("Custom headerList", func(t *testing.T) {
		algo := "rsa-sha256"
		headerList := []string{"foo", "date"}

		sessionKey := generateSession(algo, pubCertId)
		generateSpec(algo, privCertId, sessionKey, headerList)

		refDate := "Mon, 02 Jan 2006 15:04:05 MST"
		tim := time.Now().Format(refDate)

		headers := map[string]string{"foo": "bar", "date": tim}

		ts.Run(t, []test.TestCase{
			{Path: "/test/by_name", Code: 200, Headers: headers},
		}...)
	})

	t.Run("Non-existing Custom headers", func(t *testing.T) {
		algo := "rsa-sha256"
		headerList := []string{"foo"}

		sessionKey := generateSession(algo, pubCertId)
		generateSpec(algo, privCertId, sessionKey, headerList)

		ts.Run(t, []test.TestCase{
			{Path: "/test/by_name", Code: 200},
		}...)
	})
}
