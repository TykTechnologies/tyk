package gateway

import (
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/headers"

	"github.com/TykTechnologies/tyk/apidef"
	_ "github.com/TykTechnologies/tyk/headers"

	"github.com/TykTechnologies/tyk/storage"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestAuthenticationAfterDeleteKey(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	assert := func(hashKeys bool) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HashKeys = hashKeys
		ts.Gw.SetConfig(globalConf)

		ts := StartTest(nil)
		defer ts.Close()

		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})[0]

		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{api.APIID: {
				APIID: api.APIID,
			}}
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
	ts := StartTest(nil)
	defer ts.Close()

	assert := func(hashKeys bool) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HashKeys = hashKeys
		ts.Gw.SetConfig(globalConf)

		ts.RemoveApis()
		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})[0]

		key := ts.Gw.generateToken("", "")

		session := CreateStandardSession()
		session.AccessRights = map[string]user.AccessDefinition{api.APIID: {
			APIID: api.APIID,
		}}

		err := ts.Gw.GlobalSessionManager.UpdateSession(storage.HashKey(key, ts.Gw.GetConfig().HashKeys), session, 0, ts.Gw.GetConfig().HashKeys)
		if err != nil {
			t.Error("could not update session in Session Manager. " + err.Error())
		}

		authHeader := map[string]string{
			"authorization": key,
		}

		ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: authHeader, Code: http.StatusOK},
		}...)

		session.AccessRights = map[string]user.AccessDefinition{"dummy": {
			APIID: "dummy",
		}}

		err = ts.Gw.GlobalSessionManager.UpdateSession(storage.HashKey(key, ts.Gw.GetConfig().HashKeys), session, 0, ts.Gw.GetConfig().HashKeys)
		if err != nil {
			t.Error("could not update session in Session Manager. " + err.Error())
		}

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
	orgId := "default"

	//We generate the combinedPEM and get its serverCertID
	_, _, combinedPEM, _ := certs.GenServerCertificate()
	serverCertID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	client := GetTLSClient(nil, nil)
	conf := func(globalConf *config.Config) {
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLCertificates = []string{serverCertID}
		globalConf.HashKeys = true
		globalConf.HashKeyFunction = "murmur64"
		globalConf.LocalSessionCache.DisableCacheSessionState = true
	}

	ts := StartTest(conf)
	defer ts.Close()

	//add the server certificate to the gateway CertificateManager
	ts.Gw.CertificateManager.Add(combinedPEM, "")
	//We reload the gw proxy so it uses the added server certificate
	ts.ReloadGatewayProxy()

	clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID, err := ts.Gw.CertificateManager.Add(clientPEM, orgId)
	if err != nil {
		t.Fatal("certificate should be added to cert manager")
	}

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {UseCertificate: false},
		}
	})[0]

	globalConf := ts.Gw.GetConfig()
	testChangeHashFunc := func(t *testing.T, authHeader map[string]string, client *http.Client, failCode int) {
		t.Helper()

		_, _ = ts.Run(t, test.TestCase{Headers: authHeader, Client: client, Code: http.StatusOK})

		globalConf.HashKeyFunction = "sha256"
		ts.Gw.SetConfig(globalConf)

		_, _ = ts.Run(t, test.TestCase{Headers: authHeader, Client: client, Code: failCode})

		globalConf.HashKeyFunctionFallback = []string{"murmur64"}
		ts.Gw.SetConfig(globalConf)

		_, _ = ts.Run(t, test.TestCase{Headers: authHeader, Client: client, Code: http.StatusOK})

		// Reset
		globalConf.HashKeyFunction = "murmur64"
		globalConf.HashKeyFunctionFallback = nil
		ts.Gw.SetConfig(globalConf)
	}

	t.Run("custom key", func(t *testing.T) {

		const customKey = "custom-key"

		session := CreateStandardSession()
		session.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}

		_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/keys/" + customKey,
			Data: session, Client: client, Code: http.StatusOK})

		testChangeHashFunc(t, map[string]string{headers.Authorization: customKey}, client, http.StatusForbidden)
	})

	t.Run("basic auth key", func(t *testing.T) {
		api.UseBasicAuth = true
		api.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {UseCertificate: true},
		}
		ts.RemoveApis()
		ts.Gw.LoadAPI(api)
		globalConf = ts.Gw.GetConfig()

		session := CreateStandardSession()
		session.BasicAuthData.Password = "password"
		session.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}

		_, _ = ts.Run(t, test.TestCase{
			AdminAuth: true,
			Method:    http.MethodPost,
			Path:      "/tyk/keys/user",
			Data:      session,
			Client:    client,
			Code:      http.StatusOK,
		})

		authHeader := map[string]string{"Authorization": genAuthHeader("user", "password")}

		testChangeHashFunc(t, authHeader, client, http.StatusUnauthorized)

		api.UseBasicAuth = false
		ts.Gw.LoadAPI(api)
		globalConf = ts.Gw.GetConfig()
	})

	t.Run("client certificate", func(t *testing.T) {
		api.UseBasicAuth = false
		api.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {UseCertificate: true},
		}
		ts.RemoveApis()
		ts.Gw.LoadAPI(api)
		session := CreateStandardSession()
		session.Certificate = clientCertID
		session.BasicAuthData.Password = "password"
		session.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}

		_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/keys/create",
			Data: session, Client: client, Code: http.StatusOK})

		client = GetTLSClient(&clientCert, nil)
		testChangeHashFunc(t, nil, client, http.StatusForbidden)
	})

}
