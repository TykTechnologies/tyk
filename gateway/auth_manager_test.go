package gateway

import (
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/headers"

	"github.com/TykTechnologies/tyk/storage"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestAuthenticationAfterDeleteKey(t *testing.T) {
	assert := func(hashKeys bool) {
		globalConf := config.Global()
		globalConf.HashKeys = hashKeys
		config.SetGlobal(globalConf)

		ts := StartTest()
		defer ts.Close()

		api := BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})[0]

		key := CreateSession(func(s *user.SessionState) {
			s.SetAccessRights(map[string]user.AccessDefinition{api.APIID: {
				APIID: api.APIID,
			}})
		})
		deletePath := "/tyk/keys/" + key
		authHeader := map[string]string{
			"authorization": key,
		}

		ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: authHeader, Code: http.StatusOK},
			{Method: http.MethodDelete, Path: deletePath, AdminAuth: true, Code: http.StatusOK, BodyMatch: `"action":"deleted"`},
			{Path: "/get", Headers: authHeader, Code: http.StatusForbidden},
		}...)
	}

	t.Run("HashKeys=false", func(t *testing.T) {
		assert(false)
	})

	t.Run("HashKeys=true", func(t *testing.T) {
		assert(true)
	})
}

func TestAuthenticationAfterUpdateKey(t *testing.T) {
	assert := func(hashKeys bool) {
		globalConf := config.Global()
		globalConf.HashKeys = hashKeys
		config.SetGlobal(globalConf)

		ts := StartTest()
		defer ts.Close()

		api := BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})[0]

		key := generateToken("", "")

		session := CreateStandardSession()
		session.SetAccessRights(map[string]user.AccessDefinition{api.APIID: {
			APIID: api.APIID,
		}})

		GlobalSessionManager.UpdateSession(storage.HashKey(key), session, 0, config.Global().HashKeys)

		authHeader := map[string]string{
			"authorization": key,
		}

		ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: authHeader, Code: http.StatusOK},
		}...)

		session.SetAccessRights(map[string]user.AccessDefinition{"dummy": {
			APIID: "dummy",
		}})

		GlobalSessionManager.UpdateSession(storage.HashKey(key), session, 0, config.Global().HashKeys)

		ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: authHeader, Code: http.StatusForbidden},
		}...)

	}

	t.Run("HashKeys=false", func(t *testing.T) {
		assert(false)
	})

	t.Run("HashKeys=true", func(t *testing.T) {
		assert(true)
	})
}

func TestHashKeyFunctionChanged(t *testing.T) {
	_, _, combinedPEM, _ := genServerCertificate()
	serverCertID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(serverCertID, "")

	_, _, _, clientCert := genCertificate(&x509.Certificate{})
	clientCertID := certs.HexSHA256(clientCert.Certificate[0])
	client := GetTLSClient(nil, nil)

	globalConf := config.Global()
	globalConf.HttpServerOptions.UseSSL = true
	globalConf.HttpServerOptions.SSLCertificates = []string{serverCertID}
	globalConf.HashKeys = true
	globalConf.HashKeyFunction = "murmur64"
	globalConf.LocalSessionCache.DisableCacheSessionState = true
	config.SetGlobal(globalConf)

	defer ResetTestConfig()

	g := StartTest()
	defer g.Close()

	api := BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			authTokenType: {UseCertificate: true},
		}
	})[0]

	globalConf = config.Global()

	testChangeHashFunc := func(t *testing.T, authHeader map[string]string, client *http.Client, failCode int) {
		_, _ = g.Run(t, test.TestCase{Headers: authHeader, Client: client, Code: http.StatusOK})

		globalConf.HashKeyFunction = "sha256"
		config.SetGlobal(globalConf)

		_, _ = g.Run(t, test.TestCase{Headers: authHeader, Client: client, Code: failCode})

		globalConf.HashKeyFunctionFallback = []string{"murmur64"}
		config.SetGlobal(globalConf)

		_, _ = g.Run(t, test.TestCase{Headers: authHeader, Client: client, Code: http.StatusOK})

		// Reset
		globalConf.HashKeyFunction = "murmur64"
		globalConf.HashKeyFunctionFallback = nil
		config.SetGlobal(globalConf)
	}

	t.Run("custom key", func(t *testing.T) {
		const customKey = "custom-key"

		session := CreateStandardSession()
		session.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}

		_, _ = g.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/keys/" + customKey,
			Data: session, Client: client, Code: http.StatusOK})

		testChangeHashFunc(t, map[string]string{headers.Authorization: customKey}, client, http.StatusForbidden)
	})

	t.Run("basic auth key", func(t *testing.T) {
		api.UseBasicAuth = true
		LoadAPI(api)
		globalConf = config.Global()

		session := CreateStandardSession()
		session.BasicAuthData.Password = "password"
		session.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}

		_, _ = g.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/keys/user",
			Data: session, Client: client, Code: http.StatusOK})

		authHeader := map[string]string{"Authorization": genAuthHeader("user", "password")}

		testChangeHashFunc(t, authHeader, client, http.StatusUnauthorized)

		api.UseBasicAuth = false
		LoadAPI(api)
		globalConf = config.Global()
	})

	t.Run("client certificate", func(t *testing.T) {
		session := CreateStandardSession()
		session.Certificate = clientCertID
		session.BasicAuthData.Password = "password"
		session.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}

		_, _ = g.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/keys/create",
			Data: session, Client: client, Code: http.StatusOK})

		client = GetTLSClient(&clientCert, nil)
		testChangeHashFunc(t, nil, client, http.StatusForbidden)
	})
}
