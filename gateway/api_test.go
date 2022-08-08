package gateway

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/TykTechnologies/tyk/certs"

	"github.com/go-redis/redis/v8"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"fmt"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

const apiTestDef = `{
	"api_id": "1",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + TestHttpAny + `"
	}
}`

func TestHealthCheckEndpoint(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.HealthCheck.EnableHealthChecks = true
	ts.Gw.SetConfig(globalConf)

	ts.Gw.BuildAndLoadAPI()

	ts.Run(t, []test.TestCase{
		{Path: "/tyk/health/?api_id=test", AdminAuth: true, Code: 200},
		{Path: "/tyk/health/?api_id=unknown", AdminAuth: true, Code: 404, BodyMatch: `"message":"API ID not found"`},
	}...)
}

func TestApiHandlerPostDupPath(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	type testCase struct {
		APIID, ListenPath string
	}

	assertListenPaths := func(tests []testCase) {
		for _, tc := range tests {
			s := ts.Gw.getApiSpec(tc.APIID)
			if want, got := tc.ListenPath, s.Proxy.ListenPath; want != got {
				t.Errorf("API spec %s want path %s, got %s", "2", want, got)
			}
		}
	}

	t.Run("Sequentieal order", func(t *testing.T) {
		// Load initial API
		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) { spec.APIID = "1" },
		)

		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) { spec.APIID = "1" },
			func(spec *APISpec) { spec.APIID = "2" },
			func(spec *APISpec) { spec.APIID = "3" },
		)

		assertListenPaths([]testCase{
			// Should retain original API
			{"1", "/sample"},
			{"2", "/sample-2"},
			{"3", "/sample-3"},
		})
	})

	t.Run("Should re-order", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) { spec.APIID = "2" },
			func(spec *APISpec) { spec.APIID = "3" },
		)

		assertListenPaths([]testCase{
			{"2", "/sample-2"},
			{"3", "/sample-3"},
		})
	})

	t.Run("Restore original order", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) { spec.APIID = "1" },
			func(spec *APISpec) { spec.APIID = "2" },
			func(spec *APISpec) { spec.APIID = "3" },
		)

		assertListenPaths([]testCase{
			// Since API was not loaded previously first it has prefixed id
			{"1", "/sample-1"},
			{"2", "/sample-2"},
			{"3", "/sample-3"},
		})
	})
}

func TestKeyHandler(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Auth.UseParam = true
	})

	// Access right not specified
	masterKey := CreateStandardSession()
	masterKeyJSON, _ := json.Marshal(masterKey)
	//TestTykMakeHTTPRequest
	// with access
	withAccess := CreateStandardSession()
	withAccess.AccessRights = map[string]user.AccessDefinition{"test": {
		APIID: "test", Versions: []string{"v1"},
	}}
	withAccessJSON, _ := json.Marshal(withAccess)

	// with policy
	ts.Gw.policiesMu.Lock()
	ts.Gw.policiesByID["abc_policy"] = user.Policy{
		Active:           true,
		QuotaMax:         5,
		QuotaRenewalRate: 300,
		AccessRights: map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}},
		OrgID: "default",
	}
	ts.Gw.policiesMu.Unlock()
	withPolicy := CreateStandardSession()
	withoutPolicyJSON, _ := json.Marshal(withPolicy)

	withPolicy.ApplyPolicies = []string{
		"abc_policy",
	}
	withPolicyJSON, _ := json.Marshal(withPolicy)

	// with invalid policy
	withBadPolicy := CreateStandardSession()
	withBadPolicy.AccessRights = map[string]user.AccessDefinition{"test": {
		APIID: "test", Versions: []string{"v1"},
	}}
	withBadPolicy.ApplyPolicies = []string{
		"xyz_policy",
	}
	withBadPolicyJSON, _ := json.Marshal(withBadPolicy)

	t.Run("Create key", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			// Master keys should be disabled by default
			{Method: "POST", Path: "/tyk/keys/create", Data: string(masterKeyJSON), AdminAuth: true, Code: 400, BodyMatch: "Failed to create key, keys must have at least one Access Rights record set."},
			{Method: "POST", Path: "/tyk/keys/create", Data: string(withAccessJSON), AdminAuth: true, Code: 200},
		}...)
	})

	t.Run("Create key with policy", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Method:    "POST",
				Path:      "/tyk/keys/create",
				Data:      string(withoutPolicyJSON),
				AdminAuth: true,
				Code:      400,
			},
			{
				Method:    "POST",
				Path:      "/tyk/keys/create",
				Data:      string(withPolicyJSON),
				AdminAuth: true,
				Code:      200,
			},
			{
				Method:    "POST",
				Path:      "/tyk/keys/create",
				Data:      string(withBadPolicyJSON),
				AdminAuth: true,
				Code:      500,
			},
			{
				Method:    "POST",
				Path:      "/tyk/keys/my_key_id",
				Data:      string(withPolicyJSON),
				AdminAuth: true,
				Code:      200,
			},
			{
				Method: "GET",
				Path:   "/sample/?authorization=wrong_key_id",
				Code:   403,
			},
			{
				Method: "GET",
				Path:   "/sample/?authorization=my_key_id",
				Code:   200,
			},
			{
				Method:    "GET",
				Path:      "/tyk/keys/my_key_id" + "?api_id=test",
				AdminAuth: true,
				Code:      200,
				BodyMatch: `"quota_max":5`,
			},
			{
				Method:    "GET",
				Path:      "/tyk/keys/my_key_id" + "?api_id=test",
				AdminAuth: true,
				Code:      200,
				BodyMatch: `"quota_remaining":4`,
			},
		}...)

		ts.Gw.GlobalSessionManager.Store().DeleteAllKeys()
	})

	_, knownKey := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}
	})

	_, unknownOrgKey := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = "dummy"
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}
	})

	t.Run("Get key", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/tyk/keys/unknown", AdminAuth: true, Code: 404},
			{Method: "GET", Path: "/tyk/keys/" + knownKey, AdminAuth: true, Code: 200},
			{Method: "GET", Path: "/tyk/keys/" + knownKey + "?api_id=test", AdminAuth: true, Code: 200},
			{Method: "GET", Path: "/tyk/keys/" + knownKey + "?api_id=unknown", AdminAuth: true, Code: 200},
		}...)
	})

	t.Run("List keys", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/tyk/keys/", AdminAuth: true, Code: 200, BodyMatch: knownKey},
			{Method: "GET", Path: "/tyk/keys/?api_id=test", AdminAuth: true, Code: 200, BodyMatch: knownKey},
			{Method: "GET", Path: "/tyk/keys/?api_id=unknown", AdminAuth: true, Code: 200, BodyMatch: knownKey},
		}...)

		globalConf := ts.Gw.GetConfig()
		globalConf.HashKeyFunction = ""
		ts.Gw.SetConfig(globalConf)
		_, keyWithoutHash := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"test": {
				APIID: "test", Versions: []string{"v1"},
			}}
		})

		assert := func(response *http.Response, expected []string) {
			var keys apiAllKeys
			_ = json.NewDecoder(response.Body).Decode(&keys)
			actual := keys.APIKeys

			sort.Strings(expected)
			sort.Strings(actual)

			if !reflect.DeepEqual(expected, actual) {
				t.Errorf("Expected %v, actual %v", expected, actual)
			}
		}

		t.Run(`filter=""`, func(t *testing.T) {
			resp, _ := ts.Run(t, test.TestCase{Method: "GET", Path: "/tyk/keys/", AdminAuth: true, Code: 200, BodyMatch: knownKey})
			expected := []string{knownKey, unknownOrgKey, keyWithoutHash}
			assert(resp, expected)
		})

		t.Run(`filter=orgID`, func(t *testing.T) {
			resp, _ := ts.Run(t, test.TestCase{Method: "GET", Path: "/tyk/keys/?filter=" + "default", AdminAuth: true, Code: 200, BodyMatch: knownKey})
			expected := []string{knownKey, keyWithoutHash}
			assert(resp, expected)
		})
	})

	t.Run("Update key", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			// Without data
			{Method: "PUT", Path: "/tyk/keys/" + knownKey, AdminAuth: true, Code: 400},
			{Method: "PUT", Path: "/tyk/keys/" + knownKey, Data: string(withAccessJSON), AdminAuth: true, Code: 200},
			{Method: "PUT", Path: "/tyk/keys/" + knownKey + "?api_id=test", Data: string(withAccessJSON), AdminAuth: true, Code: 200},
			{Method: "PUT", Path: "/tyk/keys/" + knownKey + "?api_id=none", Data: string(withAccessJSON), AdminAuth: true, Code: 200},
		}...)
	})

	t.Run("Delete key", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{Method: "DELETE", Path: "/tyk/keys/" + knownKey, AdminAuth: true, Code: 200, BodyMatch: `"action":"deleted"`},
			{Method: "GET", Path: "/tyk/keys/" + knownKey, AdminAuth: true, Code: 404},
		}...)
	})
}

func TestKeyHandler_UpdateKey(t *testing.T) {
	const testAPIID = "testAPIID"

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.Auth.UseParam = true
		spec.OrgID = "default"
	})

	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.Partitions.RateLimit = true
		p.Tags = []string{"p1-tag"}
		p.MetaData = map[string]interface{}{
			"p1-meta": "p1-value",
		}
	})

	pID2 := ts.CreatePolicy(func(p *user.Policy) {
		p.Partitions.Quota = true
		p.Tags = []string{"p2-tag"}
		p.MetaData = map[string]interface{}{
			"p2-meta": "p2-value",
		}
	})

	session, key := ts.CreateSession(func(s *user.SessionState) {
		s.ApplyPolicies = []string{pID}
		s.Tags = []string{"key-tag1", "key-tag2"}
		s.MetaData = map[string]interface{}{
			"key-meta1": "key-value1",
			"key-meta2": "key-value2",
		}
		s.AccessRights = map[string]user.AccessDefinition{testAPIID: {
			APIID: testAPIID, Versions: []string{"v1"},
		}}
	})

	t.Run("Add policy not enforcing acl", func(t *testing.T) {
		session.ApplyPolicies = append(session.ApplyPolicies, pID2)
		sessionData, _ := json.Marshal(session)
		path := fmt.Sprintf("/tyk/keys/%s", key)

		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodPut, Path: path, Data: sessionData, AdminAuth: true, Code: 200},
		}...)

		sessionState, found := ts.Gw.GlobalSessionManager.SessionDetail("default", key, false)
		if !found || sessionState.AccessRights[testAPIID].APIID != testAPIID || len(sessionState.ApplyPolicies) != 2 {
			t.Fatal("Adding policy to the list failed")
		}
	})

	t.Run("Remove policy not enforcing acl", func(t *testing.T) {
		session.ApplyPolicies = []string{}
		sessionData, _ := json.Marshal(session)
		path := fmt.Sprintf("/tyk/keys/%s", key)

		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodPut, Path: path, Data: sessionData, AdminAuth: true, Code: 200},
		}...)

		sessionState, found := ts.Gw.GlobalSessionManager.SessionDetail("default", key, false)
		if !found || sessionState.AccessRights[testAPIID].APIID != testAPIID || len(sessionState.ApplyPolicies) != 0 {
			t.Fatal("Removing policy from the list failed")
		}
	})

	t.Run("Tags on key level", func(t *testing.T) {
		assertTags := func(session *user.SessionState, expected []string) {
			sessionData, _ := json.Marshal(session)
			path := fmt.Sprintf("/tyk/keys/%s", key)

			_, _ = ts.Run(t, []test.TestCase{
				{Method: http.MethodPut, Path: path, Data: sessionData, AdminAuth: true, Code: 200},
			}...)

			sessionState, found := ts.Gw.GlobalSessionManager.SessionDetail(session.OrgID, key, false)

			sort.Strings(sessionState.Tags)
			sort.Strings(expected)

			if !found || !reflect.DeepEqual(expected, sessionState.Tags) {
				t.Fatalf("Expected %v, returned %v", expected, sessionState.Tags)
			}
		}

		t.Run("Add", func(t *testing.T) {
			expected := []string{"p1-tag", "p2-tag", "key-tag1", "key-tag2"}
			session.ApplyPolicies = []string{pID, pID2}
			assertTags(session, expected)
		})

		t.Run("Make unique", func(t *testing.T) {
			expected := []string{"p1-tag", "p2-tag", "key-tag1", "key-tag2"}
			session.ApplyPolicies = []string{pID, pID2}
			session.Tags = append(session.Tags, "p1-tag", "key-tag1")
			assertTags(session, expected)
		})

		t.Run("Remove", func(t *testing.T) {
			expected := []string{"p1-tag", "p2-tag", "key-tag2"}
			session.ApplyPolicies = []string{pID, pID2}
			session.Tags = []string{"key-tag2"}
			assertTags(session, expected)
		})

	})

	t.Run("MetaData on key level", func(t *testing.T) {
		assertMetaData := func(session *user.SessionState, expected map[string]interface{}) {
			sessionData, _ := json.Marshal(session)
			path := fmt.Sprintf("/tyk/keys/%s", key)

			_, _ = ts.Run(t, []test.TestCase{
				{Method: http.MethodPut, Path: path, Data: sessionData, AdminAuth: true, Code: 200},
			}...)

			sessionState, found := ts.Gw.GlobalSessionManager.SessionDetail(session.OrgID, key, false)

			if !found || !reflect.DeepEqual(expected, sessionState.MetaData) {
				t.Fatalf("Expected %v, returned %v", expected, sessionState.MetaData)
			}
		}

		t.Run("Add", func(t *testing.T) {
			expected := map[string]interface{}{
				"p1-meta":   "p1-value",
				"p2-meta":   "p2-value",
				"key-meta1": "key-value1",
				"key-meta2": "key-value2",
			}
			session.ApplyPolicies = []string{pID, pID2}
			assertMetaData(session, expected)
		})

		t.Run("Make unique", func(t *testing.T) {
			expected := map[string]interface{}{
				"p1-meta":   "p1-value",
				"p2-meta":   "p2-value",
				"key-meta1": "key-value1",
				"key-meta2": "key-value2",
			}
			session.ApplyPolicies = []string{pID, pID2}
			assertMetaData(session, expected)
		})

		t.Run("Remove", func(t *testing.T) {
			expected := map[string]interface{}{
				"p1-meta":   "p1-value",
				"p2-meta":   "p2-value",
				"key-meta2": "key-value2",
			}
			session.ApplyPolicies = []string{pID, pID2}
			session.MetaData = map[string]interface{}{
				"key-meta2": "key-value2",
			}
			assertMetaData(session, expected)
		})
	})
}

func TestUpdateKeyWithCert(t *testing.T) {

	ts := StartTest(nil)
	defer ts.Close()

	apiId := "MTLSApi"
	pID := ts.CreatePolicy(func(p *user.Policy) {})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiId
		spec.UseKeylessAccess = false
		spec.Auth.UseCertificate = true
		spec.OrgID = "default"
		spec.UseStandardAuth = true
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": {UseCertificate: true},
		}
	})

	t.Run("Update key with valid cert", func(t *testing.T) {
		// create cert
		clientCertPem, _, _, _ := certs.GenCertificate(&x509.Certificate{})
		certID, _ := ts.Gw.CertificateManager.Add(clientCertPem, "")
		defer ts.Gw.CertificateManager.Delete(certID, "")

		// new valid cert
		newClientCertPem, _, _, _ := certs.GenCertificate(&x509.Certificate{})
		newCertID, _ := ts.Gw.CertificateManager.Add(newClientCertPem, "")
		defer ts.Gw.CertificateManager.Delete(newCertID, "")

		// create session base and set cert
		session, key := ts.CreateSession(func(s *user.SessionState) {
			s.ApplyPolicies = []string{pID}
			s.AccessRights = map[string]user.AccessDefinition{apiId: {
				APIID: apiId, Versions: []string{"v1"},
			}}
			s.Certificate = certID
		})

		session.Certificate = newCertID
		sessionData, _ := json.Marshal(session)

		path := fmt.Sprintf("/tyk/keys/%s", key)
		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodPut, Path: path, Data: sessionData, AdminAuth: true, Code: 200},
		}...)
	})

	t.Run("Update key with empty cert", func(t *testing.T) {
		clientCertPem, _, _, _ := certs.GenCertificate(&x509.Certificate{})
		certID, _ := ts.Gw.CertificateManager.Add(clientCertPem, "")

		// create session base and set cert
		session, key := ts.CreateSession(func(s *user.SessionState) {
			s.ApplyPolicies = []string{pID}
			s.AccessRights = map[string]user.AccessDefinition{apiId: {
				APIID: apiId, Versions: []string{"v1"},
			}}
			s.Certificate = certID
		})

		// attempt to set an empty cert
		session.Certificate = ""
		sessionData, _ := json.Marshal(session)

		path := fmt.Sprintf("/tyk/keys/%s", key)
		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodPut, Path: path, Data: sessionData, AdminAuth: true, Code: 400},
		}...)
	})

	t.Run("Update key with invalid cert", func(t *testing.T) {
		clientCertPem, _, _, _ := certs.GenCertificate(&x509.Certificate{})
		certID, _ := ts.Gw.CertificateManager.Add(clientCertPem, "")

		// create session base and set cert
		session, key := ts.CreateSession(func(s *user.SessionState) {
			s.ApplyPolicies = []string{pID}
			s.AccessRights = map[string]user.AccessDefinition{apiId: {
				APIID: apiId, Versions: []string{"v1"},
			}}
			s.Certificate = certID
		})

		session.Certificate = "invalid-cert-id"
		sessionData, _ := json.Marshal(session)

		path := fmt.Sprintf("/tyk/keys/%s", key)
		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodPut, Path: path, Data: sessionData, AdminAuth: true, Code: 400},
		}...)
	})
}

func TestKeyHandler_CheckKeysNotDuplicateOnUpdate(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Auth.UseParam = true
	})

	const shortCustomKey = "aaaa"                                     // should be bigger than 24
	const longCustomKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // should be bigger than 24

	cases := []struct {
		Name     string
		KeyName  string
		HashKeys bool
	}{
		{
			Name:     "short,custom,notHashed",
			KeyName:  shortCustomKey,
			HashKeys: false,
		},
		{
			Name:     "short,custom,hashed",
			KeyName:  shortCustomKey,
			HashKeys: true,
		},
		{
			Name:     "long,custom,notHashed",
			KeyName:  longCustomKey,
			HashKeys: false,
		},
		{
			Name:     "long,custom,hashed",
			KeyName:  longCustomKey,
			HashKeys: true,
		},
		{
			Name:     "regular,notHashed",
			HashKeys: false,
		},
		{
			Name:     "regular,hashed",
			HashKeys: true,
		},
	}

	globalConf := ts.Gw.GetConfig()
	globalConf.HashKeyFunction = ""
	ts.Gw.SetConfig(globalConf)

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			ts.Gw.GlobalSessionManager.Store().DeleteAllKeys()
			session := CreateStandardSession()
			session.AccessRights = map[string]user.AccessDefinition{"test": {
				APIID: "test", Versions: []string{"v1"},
			}}

			globalConf := ts.Gw.GetConfig()
			globalConf.HashKeys = tc.HashKeys
			ts.Gw.SetConfig(globalConf)

			keyName := tc.KeyName
			if err := ts.Gw.doAddOrUpdate(ts.Gw.generateToken(session.OrgID, keyName), session, false, tc.HashKeys); err != nil {
				t.Error("Failed to create key, ensure security settings are correct:" + err.Error())
			}

			requestByte, _ := json.Marshal(session)
			r := httptest.NewRequest(http.MethodPut, "/tyk/keys/"+keyName, bytes.NewReader(requestByte))
			ts.Gw.handleAddOrUpdate(keyName, r, tc.HashKeys)

			sessions := ts.Gw.GlobalSessionManager.Sessions("")
			if len(sessions) != 1 {
				t.Errorf("Sessions stored in global manager should be 1. But got: %v", len(sessions))
			}
		})
	}
}

func TestHashKeyHandler(t *testing.T) {

	conf := func(globalConf *config.Config) {
		// make it to use hashes for Redis keys
		globalConf.HashKeys = true
		// enable hashed keys listing
		globalConf.EnableHashedKeysListing = true
	}
	ts := StartTest(conf)
	defer ts.Close()

	hashTests := []struct {
		hashFunction     string
		expectedHashSize int
		desc             string
	}{
		{"", 8, " Legacy tokens, fallback to murmur32"},
		{storage.HashMurmur32, 8, ""},
		{storage.HashMurmur64, 16, ""},
		{storage.HashMurmur128, 32, ""},
		{storage.HashSha256, 64, ""},
		{"wrong", 16, " Should fallback to murmur64 if wrong alg"},
	}

	for _, tc := range hashTests {
		gwConf := ts.Gw.GetConfig()
		gwConf.HashKeyFunction = tc.hashFunction
		ts.Gw.SetConfig(gwConf)

		t.Run(fmt.Sprintf("%sHash fn: %s", tc.desc, tc.hashFunction), func(t *testing.T) {
			ts.testHashKeyHandlerHelper(t, tc.expectedHashSize)
		})
		t.Run(fmt.Sprintf("%sHash fn: %s and Basic Auth", tc.desc, tc.hashFunction), func(t *testing.T) {
			ts.testHashFuncAndBAHelper(t)
		})
	}
}

func TestHashKeyHandlerLegacyWithHashFunc(t *testing.T) {
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

	ts.Run(t, []test.TestCase{
		{
			Method:    "POST",
			Path:      "/tyk/keys/defaultuser",
			Data:      session,
			AdminAuth: true,
			Code:      200,
		},
		{
			Method:    "GET",
			Path:      "/tyk/keys/defaultuser?username=true&org_id=default",
			AdminAuth: true,
			Code:      200,
		},
	}...)

	// set custom hashing function and check if we still can get BA session with legacy key format
	globalConf.HashKeyFunction = storage.HashMurmur64
	ts.Gw.SetConfig(globalConf)

	ts.Run(t, []test.TestCase{
		{
			Method:    "GET",
			Path:      "/tyk/keys/defaultuser?username=true&org_id=default",
			AdminAuth: true,
			Code:      200,
		},
		{
			Method:    "DELETE",
			Path:      "/tyk/keys/defaultuser?username=true&org_id=default",
			AdminAuth: true,
			Code:      200,
			BodyMatch: `"action":"deleted"`,
		},
	}...)
}

func (ts *Test) testHashKeyHandlerHelper(t *testing.T, expectedHashSize int) {

	ts.Gw.BuildAndLoadAPI()

	withAccess := CreateStandardSession()
	withAccess.AccessRights = map[string]user.AccessDefinition{"test": {
		APIID: "test", Versions: []string{"v1"},
	}}
	withAccessJSON, _ := json.Marshal(withAccess)

	myKey := "my_key_id"
	myKeyHash := storage.HashKey(ts.Gw.generateToken("default", myKey), ts.Gw.GetConfig().HashKeys)

	if len(myKeyHash) != expectedHashSize {
		t.Errorf("Expected hash size: %d, got %d. Hash: %s. Key: %s", expectedHashSize, len(myKeyHash), myKeyHash, myKey)
	}

	t.Run("Create, get and delete key with key hashing", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			// create key
			{
				Method:    "POST",
				Path:      "/tyk/keys/create",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
				BodyMatch: `"key_hash"`,
			},
			{
				Method:    "POST",
				Path:      "/tyk/keys",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
				BodyMatch: `"key_hash"`,
			},
			// create key with custom value
			{
				Method:    "POST",
				Path:      "/tyk/keys/" + myKey,
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
				BodyMatch: fmt.Sprintf(`"key_hash":"%s"`, myKeyHash),
			},
			// Update key by hash value with specifying hashed=true
			{
				Method:    "PUT",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
				BodyMatch: fmt.Sprintf(`"key":"%s"`, myKeyHash),
			},
			// get one key by key name (API specified)
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKey + "?api_id=test",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
			},
			// get one key by hash value with specifying hashed=true (no API specified)
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
			},
			// get one key by hash value with specifying hashed=true (API specified)
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true&api_id=test",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
			},
			// get one key by hash value without specifying hashed=true
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKeyHash,
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      404,
			},
			// get list of keys' hashes, no API specified
			{
				Method:    "GET",
				Path:      "/tyk/keys",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
				BodyMatch: myKeyHash,
			},
			// get list of keys' hashes, API specified
			{
				Method:    "GET",
				Path:      "/tyk/keys?api_id=test",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
				BodyMatch: myKeyHash,
			},
			// delete one key by hash value with specifying hashed=true
			{
				Method:    "DELETE",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true&api_id=test",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
			},
			// check that key is not present any more
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true&api_id=test",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      404,
			},
		}...)
	})
}

func (ts *Test) testHashFuncAndBAHelper(t *testing.T) {

	session := ts.testPrepareBasicAuth(false)

	ts.Run(t, []test.TestCase{
		{
			Method:    "POST",
			Path:      "/tyk/keys/defaultuser",
			Data:      session,
			AdminAuth: true,
			Code:      200,
		},
		{
			Method:    "GET",
			Path:      "/tyk/keys/defaultuser?username=true&org_id=default",
			AdminAuth: true,
			Code:      200,
		},
		{
			Method:    "DELETE",
			Path:      "/tyk/keys/defaultuser?username=true&org_id=default",
			AdminAuth: true,
			Code:      200,
			BodyMatch: `"action":"deleted"`,
		},
	}...)
}

func TestHashKeyListingDisabled(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	// make it to use hashes for Redis keys
	globalConf.HashKeys = true
	// disable hashed keys listing
	globalConf.EnableHashedKeysListing = false
	ts.Gw.SetConfig(globalConf)
	ts.Gw.DoReload()

	ts.Gw.BuildAndLoadAPI()

	withAccess := CreateStandardSession()
	withAccess.AccessRights = map[string]user.AccessDefinition{"test": {
		APIID: "test", Versions: []string{"v1"},
	}}
	withAccessJSON, _ := json.Marshal(withAccess)

	myKey := "my_key_id"
	myKeyHash := storage.HashKey(ts.Gw.generateToken("default", myKey), ts.Gw.GetConfig().HashKeys)

	t.Run("Create, get and delete key with key hashing", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			// create key
			{
				Method:    "POST",
				Path:      "/tyk/keys/create",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
				BodyMatch: `"key_hash"`,
			},
			{
				Method:    "POST",
				Path:      "/tyk/keys",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
				BodyMatch: `"key_hash"`,
			},
			// create key with custom value
			{
				Method:    "POST",
				Path:      "/tyk/keys/" + myKey,
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
				BodyMatch: fmt.Sprintf(`"key_hash":"%s"`, myKeyHash),
			},
			// get one key by key name (API specified)
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKey + "?api_id=test",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
			},
			// get one key by hash value with specifying hashed=true (no API specified)
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
			},
			// get one key by hash value with specifying hashed=true (API specified)
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true&api_id=test",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
			},
			// get one key by hash value without specifying hashed=true
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKeyHash,
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      404,
			},
			// get list of keys' hashes, no API specified
			{
				Method:    "GET",
				Path:      "/tyk/keys",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      404,
			},
			// get list of keys' hashes, API specified
			{
				Method:    "GET",
				Path:      "/tyk/keys?api_id=test",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      404,
			},
			// delete one key by hash value with specifying hashed=true
			{
				Method:    "DELETE",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true&api_id=test",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      200,
			},
			// check that key is not present any more
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true&api_id=test",
				Data:      string(withAccessJSON),
				AdminAuth: true,
				Code:      404,
			},
		}...)
	})
}

func TestKeyHandler_HashingDisabled(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	// make it to NOT use hashes for Redis keys
	globalConf.HashKeys = false
	ts.Gw.SetConfig(globalConf)

	ts.Gw.BuildAndLoadAPI()

	withAccess := CreateStandardSession()
	withAccess.AccessRights = map[string]user.AccessDefinition{"test": {
		APIID: "test", Versions: []string{"v1"},
	}}
	withAccessJSON, _ := json.Marshal(withAccess)

	myKeyID := "my_key_id"
	token := ts.Gw.generateToken("default", myKeyID)
	myKeyHash := storage.HashKey(token, ts.Gw.GetConfig().HashKeys)

	t.Run("Create, get and delete key with key hashing", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
			// create key
			{
				Method:       "POST",
				Path:         "/tyk/keys/create",
				Data:         string(withAccessJSON),
				AdminAuth:    true,
				Code:         200,
				BodyNotMatch: `"key_hash"`,
			},
			{
				Method:       "POST",
				Path:         "/tyk/keys",
				Data:         string(withAccessJSON),
				AdminAuth:    true,
				Code:         200,
				BodyNotMatch: `"key_hash"`,
			},
			// create key with custom key ID
			{
				Method:       "POST",
				Path:         "/tyk/keys/" + myKeyID,
				Data:         string(withAccessJSON),
				AdminAuth:    true,
				Code:         200,
				BodyMatch:    fmt.Sprintf(`"key":"%s"`, token),
				BodyNotMatch: fmt.Sprintf(`"key_hash":"%s"`, myKeyHash),
			},
			// get one key by generated token
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + token,
				AdminAuth: true,
				Code:      200,
			},
			// get one key by hash value with specifying hashed=true (no API specified)
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true",
				AdminAuth: true,
				Code:      400,
			},
			// get one key by hash value with specifying hashed=true (API specified)
			{
				Method:    "GET",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true&api_id=test",
				AdminAuth: true,
				Code:      400,
			},
			// delete one key by hash value with specifying hashed=true
			{
				Method:    "DELETE",
				Path:      "/tyk/keys/" + myKeyHash + "?hashed=true&api_id=test",
				AdminAuth: true,
				Code:      200,
			},
		}...)
	})
}

func TestInvalidateCache(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI()

	ts.Run(t, []test.TestCase{
		{Method: "DELETE", Path: "/tyk/cache/test", AdminAuth: true, Code: 200},
		{Method: "DELETE", Path: "/tyk/cache/test/", AdminAuth: true, Code: 200},
	}...)
}

func TestGetOAuthClients(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseOauth2 = true
	})

	oauthRequest := NewClientRequest{
		ClientID:          "test",
		ClientRedirectURI: "http://localhost",
		APIID:             "test",
		ClientSecret:      "secret",
	}
	validOauthRequest, _ := json.Marshal(oauthRequest)

	ts.Run(t, []test.TestCase{
		{Path: "/tyk/oauth/clients/unknown", AdminAuth: true, Code: 404},
		{Path: "/tyk/oauth/clients/test", AdminAuth: true, Code: 200, BodyMatch: `\[\]`},
		{Method: "POST", Path: "/tyk/oauth/clients/create", AdminAuth: true, Data: string(validOauthRequest), Code: 200},
		{Path: "/tyk/oauth/clients/test", AdminAuth: true, Code: 200, BodyMatch: `\[{"client_id":"test"`},
	}...)
}

func TestCreateOAuthClient(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.UseOauth2 = true
		},
		func(spec *APISpec) {
			spec.APIID = "non_oauth_api"
			spec.UseOauth2 = false
		},
	)

	ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "p1"
		p.AccessRights = map[string]user.AccessDefinition{
			"test": {
				APIID: "test",
			},
		}
	})
	ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "p2"
		p.AccessRights = map[string]user.AccessDefinition{
			"test": {
				APIID: "test",
			},
			"abc": {
				APIID: "abc",
			},
		}
	})

	tests := map[string]struct {
		req       NewClientRequest
		code      int
		bodyMatch string
	}{
		"no api_id but policy_id provided": {
			req: NewClientRequest{
				ClientID: "client_test1",
				PolicyID: "p1",
			},
			code:      http.StatusOK,
			bodyMatch: `client_id":"client_test1"`,
		},
		"no policy_id but api_id provided": {
			req: NewClientRequest{
				ClientID: "client_test2",
				APIID:    "test",
			},
			code:      http.StatusOK,
			bodyMatch: `client_id":"client_test2"`,
		},
		// "both api_id and policy_id provided": {
		// 	req: NewClientRequest{
		// 		PolicyID: "p1",
		// 		APIID:    "test",
		// 	},
		// 	code:      http.StatusBadRequest,
		// 	bodyMatch: "both api_id and policy_id specified",
		// },
		"policy does not exist": {
			req: NewClientRequest{
				PolicyID: "unknown",
			},
			code:      http.StatusBadRequest,
			bodyMatch: "Policy doesn't exist",
		},
		"API does not exist": {
			req: NewClientRequest{
				APIID: "unknown",
			},
			code:      http.StatusBadRequest,
			bodyMatch: "API doesn't exist",
		},
		// "policy should contain only one API": {
		// 	req: NewClientRequest{
		// 		PolicyID: "p2",
		// 	},
		// 	code:      http.StatusBadRequest,
		// 	bodyMatch: "should contain only one API",
		// },
		"API is not OAuth": {
			req: NewClientRequest{
				APIID: "non_oauth_api",
			},
			code:      http.StatusBadRequest,
			bodyMatch: "API is not OAuth2",
		},
	}

	for testName, testData := range tests {
		t.Run(testName, func(t *testing.T) {
			requestData, _ := json.Marshal(testData.req)
			ts.Run(
				t,
				test.TestCase{
					Method:    http.MethodPost,
					Path:      "/tyk/oauth/clients/create",
					AdminAuth: true,
					Data:      string(requestData),
					Code:      testData.code,
					BodyMatch: testData.bodyMatch,
				},
			)
		})
	}
}

func TestUpdateOauthClientHandler(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	backupSecretCreator := createOauthClientSecret
	defer func() {
		createOauthClientSecret = backupSecretCreator
	}()

	hardcodedSecret := "MY_HARDCODED_SECRET"
	createOauthClientSecret = func() string {
		return hardcodedSecret
	}

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.UseOauth2 = true
		},
		func(spec *APISpec) {
			spec.APIID = "non_oauth_api"
			spec.UseOauth2 = false
		},
	)

	ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "p1"
		p.AccessRights = map[string]user.AccessDefinition{
			"test": {
				APIID: "test",
			},
		}
	})
	ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "p2"
		p.AccessRights = map[string]user.AccessDefinition{
			"test": {
				APIID: "test",
			},
			"abc": {
				APIID: "abc",
			},
		}
	})

	var b bytes.Buffer

	json.NewEncoder(&b).Encode(NewClientRequest{
		ClientID:    "12345",
		APIID:       "test",
		PolicyID:    "p1",
		Description: "MyOriginalDescription",
	})

	ts.Run(
		t,
		test.TestCase{
			Method:    http.MethodPost,
			Path:      "/tyk/oauth/clients/create",
			AdminAuth: true,
			Data:      b.String(),
			Code:      http.StatusOK,
			BodyMatch: `"client_id":"12345"`,
		},
	)

	tests := map[string]struct {
		req          NewClientRequest
		code         int
		bodyMatch    string
		bodyNotMatch string
	}{
		"Update description": {
			req: NewClientRequest{
				ClientID:    "12345",
				APIID:       "test",
				PolicyID:    "p1",
				Description: "Updated field",
			},
			code:         http.StatusOK,
			bodyMatch:    `"description":"Updated field"`,
			bodyNotMatch: "",
		},
		"Secret remains the same": {
			req: NewClientRequest{
				ClientID:    "12345",
				APIID:       "test",
				PolicyID:    "p2",
				Description: "MyOriginalDescription",
			},
			code:         http.StatusOK,
			bodyMatch:    fmt.Sprintf(`"secret":"%s"`, hardcodedSecret),
			bodyNotMatch: "",
		},
		"Secret cannot be updated": {
			req: NewClientRequest{
				ClientID:     "12345",
				APIID:        "test",
				PolicyID:     "p1",
				Description:  "Updated field",
				ClientSecret: "super-new-secret",
			},
			code:         http.StatusOK,
			bodyNotMatch: `"secret":"super-new-secret"`,
			bodyMatch:    fmt.Sprintf(`"secret":"%s"`, hardcodedSecret),
		},
	}

	for testName, testData := range tests {
		t.Run(testName, func(t *testing.T) {
			requestData, _ := json.Marshal(testData.req)
			testCase := test.TestCase{
				Method:    http.MethodPut,
				Path:      "/tyk/oauth/clients/test/12345",
				AdminAuth: true,
				Data:      string(requestData),
				Code:      testData.code,
			}

			if testData.bodyMatch != "" {
				testCase.BodyMatch = testData.bodyMatch
			}

			if testData.bodyNotMatch != "" {
				testCase.BodyNotMatch = testData.bodyNotMatch
			}

			ts.Run(t, testCase)
		})
	}
}

func TestGroupResetHandler(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	didSubscribe := make(chan bool)
	didReload := make(chan bool)
	cacheStore := storage.RedisCluster{RedisController: ts.Gw.RedisController}
	cacheStore.Connect()

	go func() {
		err := cacheStore.StartPubSubHandler(RedisPubSubChannel, func(v interface{}) {
			switch x := v.(type) {
			case *redis.Subscription:
				didSubscribe <- true
			case *redis.Message:
				notf := Notification{Gw: ts.Gw}
				if err := json.Unmarshal([]byte(x.Payload), &notf); err != nil {
					t.Error(err)
				}
				if notf.Command == NoticeGroupReload {
					didReload <- true
				}
			}
		})
		if err != nil {
			t.Log(err)
			t.Fail()
			close(didReload)
		}
	}()

	uri := "/tyk/reload/group"

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID = make(map[string]*APISpec)
	ts.Gw.apisMu.Unlock()

	ts.Gw.LoadSampleAPI(apiTestDef)

	recorder := httptest.NewRecorder()

	// If we don't wait for the subscription to be done, we might do
	// the reload before pub/sub is in place to receive our message.
	<-didSubscribe
	req := ts.withAuth(TestReq(t, "GET", uri, nil))

	ts.mainRouter().ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Fatal("Hot reload (group) failed, response code was: ", recorder.Code)
	}

	ts.Gw.apisMu.RLock()
	if len(ts.Gw.apisByID) == 0 {
		t.Fatal("Hot reload (group) was triggered but no APIs were found.")
	}
	ts.Gw.apisMu.RUnlock()

	// We wait for the right notification (NoticeGroupReload), other
	// type of notifications may be received during tests, as this
	// is the cluster channel:
	<-didReload
}

func TestHotReloadSingle(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()
	oldRouter := ts.mainRouter()

	cfg := ts.Gw.GetConfig()
	//Changing the UseSSL option so the main router change its protocol
	cfg.HttpServerOptions.UseSSL = true
	ts.Gw.SetConfig(cfg)

	var wg sync.WaitGroup
	wg.Add(1)
	ts.Gw.reloadURLStructure(wg.Done)
	ts.Gw.ReloadTestCase.TickOk(t)
	wg.Wait()
	if ts.mainRouter() == oldRouter {
		t.Fatal("router wasn't swapped")
	}
}

func BenchmarkApiReload(b *testing.B) {
	ts := StartTest(nil)
	defer ts.Close()

	b.ReportAllocs()

	specs := make([]*APISpec, 100)

	for i := 0; i < 100; i++ {
		specs[i] = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = strconv.Itoa(i + 1)
		})[0]
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ts.Gw.loadControlAPIEndpoints(nil)
		ts.Gw.loadApps(specs)
	}
}

func TestContextData(t *testing.T) {
	r := new(http.Request)
	if ctxGetData(r) != nil {
		t.Fatal("expected ctxGetData to return nil")
	}
	ctxSetData(r, map[string]interface{}{"foo": "bar"})
	if ctxGetData(r) == nil {
		t.Fatal("expected ctxGetData to return non-nil")
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected ctxSetData of zero val to panic")
		}
	}()
	ctxSetData(r, nil)
}

func TestContextSession(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	r := new(http.Request)
	if ctxGetSession(r) != nil {
		t.Fatal("expected ctxGetSession to return nil")
	}

	ctxSetSession(r,
		&user.SessionState{},
		false,
		false)

	if ctxGetSession(r) == nil {
		t.Fatal("expected ctxGetSession to return non-nil")
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected ctxSetSession of zero val to panic")
		}
	}()
	ctxSetSession(r, nil, false, false)
}

func TestApiLoaderLongestPathFirst(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.EnableCustomDomains = true
	})
	defer ts.Close()

	type hostAndPath struct {
		host, path string
	}

	inputs := map[hostAndPath]bool{}
	hosts := []string{"host1.local", "host2.local", "host3.local"}
	paths := []string{"a", "ab", "a/b/c", "ab/c", "abc", "a/b/c"}
	// Use a map so that we get a somewhat random order when
	// iterating. Would be better to use math/rand.Shuffle once we
	// need only support Go 1.10 and later.
	for _, host := range hosts {
		for _, path := range paths {
			inputs[hostAndPath{host, path}] = true
		}
	}

	var apis []*APISpec

	for hp := range inputs {
		apis = append(apis, BuildAPI(func(spec *APISpec) {
			spec.APIID = uuid.NewV4().String()
			spec.Domain = hp.host
			spec.Proxy.ListenPath = "/" + hp.path
		})[0])
	}

	ts.Gw.LoadAPI(apis...)

	var testCases []test.TestCase

	for hp := range inputs {
		testCases = append(testCases, test.TestCase{
			Path:      "/" + hp.path,
			Domain:    hp.host,
			Code:      200,
			BodyMatch: `"Url":"/` + hp.path + `"`,
		})
	}

	ts.Run(t, testCases...)
}

func TestRotateClientSecretHandler(t *testing.T) {

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.UseOauth2 = true
		},
		func(spec *APISpec) {
			spec.APIID = "non_oauth_api"
			spec.UseOauth2 = false
		},
	)

	ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "p1"
		p.AccessRights = map[string]user.AccessDefinition{
			"test": {
				APIID: "test",
			},
		}
	})
	ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "p2"
		p.AccessRights = map[string]user.AccessDefinition{
			"test": {
				APIID: "test",
			},
			"abc": {
				APIID: "abc",
			},
		}
	})

	var b bytes.Buffer

	json.NewEncoder(&b).Encode(NewClientRequest{
		ClientID: "12345",
		APIID:    "test",
		PolicyID: "p1",
	})

	resp, err := ts.Run(
		t,
		test.TestCase{
			Method:    http.MethodPost,
			Path:      "/tyk/oauth/clients/create",
			AdminAuth: true,
			Data:      b.String(),
			Code:      http.StatusOK,
			BodyMatch: `"client_id":"12345"`,
		},
	)

	if err != nil {
		t.Error(err)

	}

	var client NewClientRequest

	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		t.Error(err)
	}

	tests := map[string]struct {
		req          NewClientRequest
		code         int
		bodyMatch    string
		bodyNotMatch string
	}{
		"Secret can be rotated": {
			req: NewClientRequest{
				ClientID: "12345",
				APIID:    "test",
				PolicyID: "p1",
			},
			code:         http.StatusOK,
			bodyNotMatch: fmt.Sprintf(`"secret":%s`, client.ClientSecret),
		},
	}

	for testName, testData := range tests {
		t.Run(testName, func(t *testing.T) {
			requestData, _ := json.Marshal(testData.req)
			testCase := test.TestCase{
				Method:    http.MethodPut,
				Path:      "/tyk/oauth/clients/test/12345/rotate",
				AdminAuth: true,
				Data:      string(requestData),
				Code:      testData.code,
			}

			if testData.bodyMatch != "" {
				testCase.BodyMatch = testData.bodyMatch
			}

			if testData.bodyNotMatch != "" {
				testCase.BodyNotMatch = testData.bodyNotMatch
			}

			ts.Run(t, testCase)
		})
	}
}

func TestHandleAddOrUpdateApi(t *testing.T) {
	testFs := afero.NewMemMapFs()

	ts := StartTest(nil)
	defer ts.Close()

	t.Run("should return error when api definition json is invalid", func(t *testing.T) {
		apiDefJson := []byte("{")
		req, err := http.NewRequest(http.MethodPost, "http://gateway", bytes.NewBuffer(apiDefJson))
		require.NoError(t, err)

		response, statusCode := ts.Gw.handleAddOrUpdateApi("", req, testFs)
		errorResponse, ok := response.(apiStatusMessage)
		require.True(t, ok)

		assert.Equal(t, "Request malformed", errorResponse.Message)
		assert.Equal(t, http.StatusBadRequest, statusCode)
	})

	t.Run("should return error when api ids are different", func(t *testing.T) {
		apiDef := apidef.DummyAPI()
		apiDef.APIID = "123"
		apiDefJson, err := json.Marshal(apiDef)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, "http://gateway", bytes.NewBuffer(apiDefJson))
		require.NoError(t, err)

		response, statusCode := ts.Gw.handleAddOrUpdateApi("555", req, testFs)
		errorResponse, ok := response.(apiStatusMessage)
		require.True(t, ok)

		assert.Equal(t, "Request APIID does not match that in Definition! For Update operations these must match.", errorResponse.Message)
		assert.Equal(t, http.StatusBadRequest, statusCode)
	})

	t.Run("should return error when semantic validation fails", func(t *testing.T) {
		apiDef := apidef.DummyAPI()
		apiDef.APIID = "123"
		apiDef.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Name: "duplicate",
			},
			{
				Name: "duplicate",
			},
		}
		apiDefJson, err := json.Marshal(apiDef)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, "http://gateway", bytes.NewBuffer(apiDefJson))
		require.NoError(t, err)

		response, statusCode := ts.Gw.handleAddOrUpdateApi("", req, testFs)
		errorResponse, ok := response.(apiStatusMessage)
		require.True(t, ok)

		assert.Equal(t, "Validation of API Definition failed. Reason: duplicate data source names are not allowed.", errorResponse.Message)
		assert.Equal(t, http.StatusBadRequest, statusCode)
	})

	t.Run("should return success when no error occurs", func(t *testing.T) {
		apiDef := apidef.DummyAPI()
		apiDef.APIID = "123"
		apiDefJson, err := json.Marshal(apiDef)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, "http://gateway", bytes.NewBuffer(apiDefJson))
		require.NoError(t, err)

		response, statusCode := ts.Gw.handleAddOrUpdateApi("", req, testFs)
		successResponse, ok := response.(apiModifyKeySuccess)
		require.True(t, ok)

		assert.Equal(t, "123", successResponse.Key)
		assert.Equal(t, "added", successResponse.Action)
		assert.Equal(t, http.StatusOK, statusCode)
	})
}

func TestApplyLifetime(t *testing.T) {

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.APIID = "api1"
		},
		func(spec *APISpec) {
			spec.APIID = "api2"
			spec.SessionLifetime = 1000
		},
		func(spec *APISpec) {
			spec.APIID = "api3"
			spec.SessionLifetime = 999
		},
	)

	testCases := []struct {
		name             string
		expectedLifetime int64
		getTestSession   func() user.SessionState
	}{
		{
			name:             "single api without session lifetime set",
			expectedLifetime: 0,
			getTestSession: func() user.SessionState {
				return user.SessionState{
					AccessRights: map[string]user.AccessDefinition{
						"api1": {
							APIID: "api1", Versions: []string{"v1"},
						},
					},
				}
			},
		},
		{
			name:             "many apis, one of them with session lifetime set",
			expectedLifetime: 1000,
			getTestSession: func() user.SessionState {
				return user.SessionState{
					AccessRights: map[string]user.AccessDefinition{
						"api1": {
							APIID: "api1", Versions: []string{"v1"},
						},
						"api2": {
							APIID: "api2", Versions: []string{"v1"},
						},
					},
				}
			},
		},
		{
			name:             "many apis with session lifetime set, greater should be used",
			expectedLifetime: 1000,
			getTestSession: func() user.SessionState {
				return user.SessionState{
					AccessRights: map[string]user.AccessDefinition{
						"api2": {
							APIID: "api2", Versions: []string{"v1"},
						},
						"api3": {
							APIID: "api3", Versions: []string{"v1"},
						},
					},
				}
			},
		},
		{
			name:             "Session without access rights",
			expectedLifetime: 0,
			getTestSession: func() user.SessionState {
				return user.SessionState{}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := tc.getTestSession()
			assert.Equal(t, tc.expectedLifetime, ts.Gw.ApplyLifetime(&session, nil))
		})
	}
}
