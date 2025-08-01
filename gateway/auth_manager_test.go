package gateway

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/header"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestAuthenticationAfterDeleteKey(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	assert := func(t *testing.T, ts *Test, hashKeys bool) {
		t.Helper()
		globalConf := ts.Gw.GetConfig()
		globalConf.HashKeys = hashKeys
		ts.Gw.SetConfig(globalConf)

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
		assert(t, ts, false)
	})

	t.Run("HashKeys=true", func(t *testing.T) {
		assert(t, ts, true)
	})
}

func TestAuthenticationAfterUpdateKey(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	assert := func(t *testing.T, ts *Test, hashKeys bool) {
		t.Helper()
		globalConf := ts.Gw.GetConfig()
		globalConf.HashKeys = hashKeys
		ts.Gw.SetConfig(globalConf)

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
		assert(t, ts, false)
	})

	t.Run("HashKeys=true", func(t *testing.T) {
		assert(t, ts, true)
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
		// Test with custom authentication key
		const customKey = "custom-key"

		session := CreateStandardSession()
		session.AccessRights = map[string]user.AccessDefinition{api.APIID: {
			APIID: api.APIID, Versions: []string{"v1"},
		}}

		// Create the session with the custom key
		_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/keys/" + customKey,
			Data: session, Client: client, Code: http.StatusOK})

		// Test that changing hash function breaks then fixes authentication
		testChangeHashFunc(t, map[string]string{header.Authorization: customKey}, client, http.StatusForbidden)
	})

	t.Run("basic auth key", func(t *testing.T) {
		// Test with basic authentication using username/password
		api.UseBasicAuth = true
		api.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {UseCertificate: false},
		}
		ts.Gw.LoadAPI(api)
		globalConf = ts.Gw.GetConfig()

		session := CreateStandardSession()
		session.BasicAuthData.Password = "password"
		session.AccessRights = map[string]user.AccessDefinition{api.APIID: {
			APIID: api.APIID, Versions: []string{"v1"},
		}}

		// Create the session with username "user" and password "password"
		_, _ = ts.Run(t, test.TestCase{
			AdminAuth: true,
			Method:    http.MethodPost,
			Path:      "/tyk/keys/user",
			Data:      session,
			Client:    client,
			Code:      http.StatusOK,
		})

		authHeader := map[string]string{"Authorization": genAuthHeader("user", "password")}

		// Test that changing hash function breaks then fixes authentication
		testChangeHashFunc(t, authHeader, client, http.StatusUnauthorized)

		// Reset API configuration
		api.UseBasicAuth = false
		ts.Gw.LoadAPI(api)
		globalConf = ts.Gw.GetConfig()
	})

	t.Run("client certificate", func(t *testing.T) {
		// Test with client certificate authentication
		api.UseBasicAuth = false
		api.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {UseCertificate: true},
		}
		ts.Gw.LoadAPI(api)

		session := CreateStandardSession()
		session.Certificate = clientCertID
		session.BasicAuthData.Password = "password"
		session.AccessRights = map[string]user.AccessDefinition{api.APIID: {
			APIID: api.APIID, Versions: []string{"v1"},
		}}

		// Create the session with client certificate authentication
		_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/keys/create",
			Data: session, Client: client, Code: http.StatusOK})

		// Use TLS client with certificate for authentication
		client = GetTLSClient(&clientCert, nil)
		// Test that changing hash function breaks then fixes authentication
		testChangeHashFunc(t, nil, client, http.StatusForbidden)
	})

}

func TestResetQuotaObfuscate(t *testing.T) {

	t.Run("Obfuscate key", func(t *testing.T) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = false
			globalConf.EnableKeyLogging = false
		}

		ts := StartTest(conf)
		sessionManager := DefaultSessionManager{Gw: ts.Gw}
		t.Cleanup(func() {
			ts.Close()
		})

		actual := sessionManager.ResetQuotaObfuscateKey("481408ygjkbs")

		assert.Equal(t, "****jkbs", actual)
	})
	t.Run("Does not Obfuscate key", func(t *testing.T) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = true
			globalConf.EnableKeyLogging = true
		}

		ts := StartTest(conf)
		sessionManager := DefaultSessionManager{Gw: ts.Gw}
		t.Cleanup(func() {
			ts.Close()
		})

		actual := sessionManager.ResetQuotaObfuscateKey("481408ygjkbs")

		assert.Equal(t, "481408ygjkbs", actual)
	})
}

// TestCustomKeysEdgeGw check that custom keys are processed
// by edge gw when a keySpace signal is received
func TestCustomKeysEdgeGw(t *testing.T) {

	const customKey = "my-custom-key"
	orgId := "default"

	testCases := []struct {
		name         string
		useCustomKey bool
	}{
		{
			name:         "sending event with custom key",
			useCustomKey: true,
		},
		{
			name:         "sending event with base64 representation",
			useCustomKey: false,
		},
	}

	hashKeys := []bool{true, false}
	for _, hashed := range hashKeys {
		t.Run(fmt.Sprintf("HashKeys: %v", hashed), func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					// 1- execute an edge gw
					ts := StartTest(func(globalConf *config.Config) {
						globalConf.SlaveOptions.GroupID = "group"
						globalConf.LivenessCheck.CheckDuration = 1000000000
						globalConf.SlaveOptions.APIKey = "apikey-test"
						globalConf.HashKeys = hashed
						globalConf.SlaveOptions.SynchroniserEnabled = hashed
					})
					defer ts.Close()

					rpcListener := RPCStorageHandler{
						KeyPrefix:        "rpc.listener.",
						SuppressRegister: true,
						HashKeys:         hashed,
						Gw:               ts.Gw,
					}

					key := customKey
					if !tc.useCustomKey {
						key = ts.Gw.generateToken(orgId, key)
					}

					// 2- creates a custom key
					session := CreateStandardSession()
					session.AccessRights = map[string]user.AccessDefinition{"test": {
						APIID: "test", Versions: []string{"v1"},
					}}
					client := GetTLSClient(nil, nil)

					resp, err := ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/keys/" + customKey,
						Data: session, Client: client, Code: http.StatusOK})
					assert.Nil(t, err)
					defer func() {
						err = resp.Body.Close()
						assert.Nil(t, err)
					}()

					body, err := io.ReadAll(resp.Body)
					assert.Nil(t, err)
					keyResp := apiModifyKeySuccess{}
					err = json.Unmarshal(body, &keyResp)
					assert.NoError(t, err)

					if hashed {
						key = keyResp.KeyHash
					}

					// 3- double check that key exists
					_, found := ts.Gw.GlobalSessionManager.SessionDetail(orgId, key, hashed)
					assert.True(t, found)

					keyEvent := key
					if hashed {
						keyEvent += ":hashed"
					}
					// 4- emit events so edge process it
					rpcListener.ProcessKeySpaceChanges([]string{keyEvent}, orgId)

					// 5- key should not exist in edge as it was removed
					_, found = ts.Gw.GlobalSessionManager.SessionDetail(orgId, key, hashed)
					assert.False(t, found)
				})
			}
		})

	}

}

func TestDeleteRawKeysWithAllowanceScope(t *testing.T) {
	sessionManager := DefaultSessionManager{}

	t.Run("should not panic if storage.Handler is nil", func(t *testing.T) {
		session := &user.SessionState{
			AccessRights: map[string]user.AccessDefinition{
				"ar1": {AllowanceScope: "scope1"},
			},
		}

		sessionManager.deleteRawKeysWithAllowanceScope(nil, session, "keyName")
	})

	t.Run("should not panic if session is nil", func(t *testing.T) {
		handler := newCountingStorageHandler()
		sessionManager.deleteRawKeysWithAllowanceScope(handler, nil, "keyName")

		assert.Equal(t, 0, handler.deleteRawKeyCount)
	})

	t.Run("should not call DeleteRawKey of the storage handler if no allowance scope is defined in any AccessDefinition", func(t *testing.T) {
		// Lets create 10,000 elements, see TT-11721
		const elementsCount = 10_000
		accessRights := make(map[string]user.AccessDefinition, elementsCount)
		for i := 0; i < elementsCount; i++ {
			key := fmt.Sprintf("ar-%d", i)
			accessRights[key] = user.AccessDefinition{AllowanceScope: ""}
		}

		session := &user.SessionState{
			AccessRights: accessRights,
		}

		handler := newCountingStorageHandler()
		sessionManager.deleteRawKeysWithAllowanceScope(handler, session, "keyName")

		assert.Equal(t, 0, handler.deleteRawKeyCount)
	})

	t.Run("should only call DeleteRawKey of the storage handler as many times as allowance scopes are defined", func(t *testing.T) {
		session := &user.SessionState{
			AccessRights: map[string]user.AccessDefinition{
				"ar1": {AllowanceScope: ""},
				"ar2": {AllowanceScope: "scope2"},
				"ar3": {AllowanceScope: "scope3"},
				"ar4": {AllowanceScope: ""},
			},
		}

		handler := newCountingStorageHandler()
		sessionManager.deleteRawKeysWithAllowanceScope(handler, session, "keyName")

		assert.Equal(t, 2, handler.deleteRawKeyCount)
	})
}

type countingStorageHandler struct {
	deleteRawKeyMutex *sync.Mutex
	deleteRawKeyCount int
}

func newCountingStorageHandler() *countingStorageHandler {
	return &countingStorageHandler{
		deleteRawKeyMutex: &sync.Mutex{},
		deleteRawKeyCount: 0,
	}
}

func (c *countingStorageHandler) GetKey(s string) (string, error) {
	return "", nil
}

func (c *countingStorageHandler) GetMultiKey(strings []string) ([]string, error) {
	return nil, nil
}

func (c *countingStorageHandler) GetRawKey(s string) (string, error) {
	return "", nil
}

func (c *countingStorageHandler) SetKey(s string, s2 string, i int64) error {
	return nil
}

func (c *countingStorageHandler) SetRawKey(s string, s2 string, i int64) error {
	return nil
}

func (c *countingStorageHandler) SetExp(s string, i int64) error {
	return nil
}

func (c *countingStorageHandler) GetExp(s string) (int64, error) {
	return 0, nil
}

func (c *countingStorageHandler) GetKeys(s string) []string {
	return nil
}

func (c *countingStorageHandler) DeleteKey(s string) bool {
	return false
}

func (c *countingStorageHandler) DeleteAllKeys() bool {
	return false
}

func (c *countingStorageHandler) DeleteRawKey(s string) bool {
	c.deleteRawKeyMutex.Lock()
	defer c.deleteRawKeyMutex.Unlock()
	c.deleteRawKeyCount++
	return true
}

func (c *countingStorageHandler) DeleteRawKeys(keys []string) bool {
	c.deleteRawKeyMutex.Lock()
	defer c.deleteRawKeyMutex.Unlock()
	c.deleteRawKeyCount += len(keys)
	return true
}

func (c *countingStorageHandler) Connect() bool {
	return false
}

func (c *countingStorageHandler) GetKeysAndValues() map[string]string {
	return nil
}

func (c *countingStorageHandler) GetKeysAndValuesWithFilter(s string) map[string]string {
	return nil
}

func (c *countingStorageHandler) DeleteKeys(_ []string) bool {
	return false
}

func (c *countingStorageHandler) Decrement(s string) {}

func (c *countingStorageHandler) IncrememntWithExpire(s string, i int64) int64 {
	return 0
}

func (c *countingStorageHandler) SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{}) {
	return 0, nil
}

func (c *countingStorageHandler) GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{}) {
	return 0, nil
}

func (c *countingStorageHandler) GetSet(s string) (map[string]string, error) {
	return nil, nil
}

func (c *countingStorageHandler) AddToSet(s string, s2 string) {}

func (c *countingStorageHandler) GetAndDeleteSet(s string) []interface{} {
	return nil
}

func (c *countingStorageHandler) RemoveFromSet(s string, s2 string) {}

func (c *countingStorageHandler) DeleteScanMatch(s string) bool {
	return false
}

func (c *countingStorageHandler) GetKeyPrefix() string {
	return ""
}

func (c *countingStorageHandler) AddToSortedSet(s string, s2 string, f float64) {}

func (c *countingStorageHandler) GetSortedSetRange(s string, s2 string, s3 string) ([]string, []float64, error) {
	return nil, nil, nil
}

func (c *countingStorageHandler) RemoveSortedSetRange(s string, s2 string, s3 string) error {
	return nil
}

func (c *countingStorageHandler) GetListRange(s string, i int64, i2 int64) ([]string, error) {
	return nil, nil
}

func (c *countingStorageHandler) RemoveFromList(s string, s2 string) error {
	return nil
}

func (c *countingStorageHandler) AppendToSet(s string, s2 string) {}

func (c *countingStorageHandler) Exists(s string) (bool, error) {
	return false, nil
}
