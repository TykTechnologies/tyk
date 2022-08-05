package gateway

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-redis/redis/v8"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func getStrPointer(str string) *string {
	return &str
}

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

const defaultTestPol = `{
"ID": "default-test",
"rate": 1000,
"per": 1,
"quota_max": 100,
"quota_renewal_rate": 60,
"access_rights": {
"41433797848f41a558c1573d3e55a410": {
"api_name": "My API",
"api_id": "41433797848f41a558c1573d3e55a410",
"versions": [
"Default"
]
}
},
"org_id": "54de205930c55e15bd000001",
"hmac_enabled": false

}`

func TestPolicyAPI(t *testing.T) {
	ts := StartTest(nil)
	globalConf := ts.Gw.GetConfig()
	globalConf.Policies.PolicyPath = "."
	globalConf.Policies.PolicySource = "file"
	ts.Gw.SetConfig(globalConf)

	defer ts.Close()
	ts.Gw.BuildAndLoadAPI()

	// test non existing policy
	_, _ = ts.Run(t, test.TestCase{
		Path: "/tyk/policies/not-here", AdminAuth: true, Method: "GET", BodyMatch: `{"status":"error","message":"Policy not found"}`, Code: http.StatusNotFound,
	})
	// create new policy
	_, _ = ts.Run(t, test.TestCase{
		Path: "/tyk/policies/default-test", AdminAuth: true, Method: "POST", Data: defaultTestPol, BodyMatch: `{"key":"default-test","status":"ok","action":"added"}`,
	})
	_, _ = ts.Run(t, test.TestCase{
		Path: "/tyk/policies/default-test", AdminAuth: true, Method: "GET", BodyMatch: `{"status":"error","message":"Policy not found"}`, Code: http.StatusNotFound,
	})
	ts.Gw.DoReload()
	_, _ = ts.Run(t, test.TestCase{
		Path: "/tyk/policies/default-test", AdminAuth: true, Method: "GET", Code: http.StatusOK,
	})
	_, _ = ts.Run(t, test.TestCase{
		Path: "/tyk/policies/default-test", AdminAuth: true, Method: "PUT", Data: defaultTestPol, BodyMatch: `{"key":"default-test","status":"ok","action":"modified"}`,
	})
	// policy still should not be reverted
	_, _ = ts.Run(t, test.TestCase{
		Path: "/tyk/policies/not-here", AdminAuth: true, Method: "GET", BodyMatch: `{"status":"error","message":"Policy not found"}`, Code: http.StatusNotFound,
	})
	ts.Gw.DoReload()
	// after reload should revert policy
	_, _ = ts.Run(t, test.TestCase{
		Path: "/tyk/policies/default-test", AdminAuth: true, Method: "GET", Code: http.StatusOK,
	})
	_, _ = ts.Run(t, test.TestCase{
		Path: "/tyk/policies/default-test", AdminAuth: true, Method: "DELETE", BodyMatch: `{"key":"default-test","status":"ok","action":"deleted"}`,
	})
	// even we delete policy should be reverted before we reload
	_, _ = ts.Run(t, test.TestCase{
		Path: "/tyk/policies/default-test", AdminAuth: true, Method: "GET", Code: http.StatusOK,
	})
	ts.Gw.DoReload()
	_, _ = ts.Run(t, test.TestCase{
		Path: "/tyk/policies/not-here", AdminAuth: true, Method: "GET", BodyMatch: `{"status":"error","message":"Policy not found"}`, Code: http.StatusNotFound,
	})
}

func TestHealthCheckEndpoint(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.HealthCheck.EnableHealthChecks = true
	ts.Gw.SetConfig(globalConf)

	ts.Gw.BuildAndLoadAPI()

	_, _ = ts.Run(t, []test.TestCase{
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
		_, _ = ts.Run(t, []test.TestCase{
			// Master keys should be disabled by default
			{Method: "POST", Path: "/tyk/keys/create", Data: string(masterKeyJSON), AdminAuth: true, Code: 400, BodyMatch: "Failed to create key, keys must have at least one Access Rights record set."},
			{Method: "POST", Path: "/tyk/keys/create", Data: string(withAccessJSON), AdminAuth: true, Code: 200},
		}...)
	})

	t.Run("Create key with policy", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
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
		_, _ = ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/tyk/keys/unknown", AdminAuth: true, Code: 404},
			{Method: "GET", Path: "/tyk/keys/" + knownKey, AdminAuth: true, Code: 200},
			{Method: "GET", Path: "/tyk/keys/" + knownKey + "?api_id=test", AdminAuth: true, Code: 200},
			{Method: "GET", Path: "/tyk/keys/" + knownKey + "?api_id=unknown", AdminAuth: true, Code: 200},
		}...)
	})

	t.Run("List keys", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
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
		_, _ = ts.Run(t, []test.TestCase{
			// Without data
			{Method: "PUT", Path: "/tyk/keys/" + knownKey, AdminAuth: true, Code: 400},
			{Method: "PUT", Path: "/tyk/keys/" + knownKey, Data: string(withAccessJSON), AdminAuth: true, Code: 200},
			{Method: "PUT", Path: "/tyk/keys/" + knownKey + "?api_id=test", Data: string(withAccessJSON), AdminAuth: true, Code: 200},
			{Method: "PUT", Path: "/tyk/keys/" + knownKey + "?api_id=none", Data: string(withAccessJSON), AdminAuth: true, Code: 200},
		}...)
	})

	t.Run("Delete key", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
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
		clientCertPem, _, _, _ := certs.GenCertificate(&x509.Certificate{}, false)
		certID, _ := ts.Gw.CertificateManager.Add(clientCertPem, "")
		defer ts.Gw.CertificateManager.Delete(certID, "")

		// new valid cert
		newClientCertPem, _, _, _ := certs.GenCertificate(&x509.Certificate{}, false)
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
		clientCertPem, _, _, _ := certs.GenCertificate(&x509.Certificate{}, false)
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
		clientCertPem, _, _, _ := certs.GenCertificate(&x509.Certificate{}, false)
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
	test.Racy(t) // TODO: TT-5233
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
	test.Racy(t) // TODO: TT-5233
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

	_, _ = ts.Run(t, []test.TestCase{
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

	_, _ = ts.Run(t, []test.TestCase{
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
		_, _ = ts.Run(t, []test.TestCase{
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

	_, _ = ts.Run(t, []test.TestCase{
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
		_, _ = ts.Run(t, []test.TestCase{
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
	test.Racy(t) // TODO: TT-5524

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

func TestSessionLifetimeRespectsKeyExpiration(t *testing.T) {
	const respectingAPI = "respectingAPI"
	const overridingAPI = "overridingAPI"

	ts := StartTest(nil)
	defer ts.Close()

	t.Run("override session lifetime with api level", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = overridingAPI
			spec.UseKeylessAccess = false
			spec.SessionLifetime = 1
			spec.SessionLifetimeRespectsKeyExpiration = false
		})

		_, toBeOverriddenKey := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{overridingAPI: {
				APIID: overridingAPI,
			}}
		})

		_, _ = ts.Run(t, []test.TestCase{
			{AdminAuth: true, Path: "/tyk/keys/" + toBeOverriddenKey, Code: http.StatusOK, Delay: time.Second},
			{AdminAuth: true, Path: "/tyk/keys/" + toBeOverriddenKey, Code: http.StatusNotFound},
		}...)
	})

	t.Run("respect key expiration", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = respectingAPI
			spec.UseKeylessAccess = false
			spec.SessionLifetime = 1
			spec.SessionLifetimeRespectsKeyExpiration = true
		})

		_, toBeRespectedKey := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{respectingAPI: {
				APIID: respectingAPI,
			}}
		})

		_, _ = ts.Run(t, []test.TestCase{
			{AdminAuth: true, Path: "/tyk/keys/" + toBeRespectedKey, Code: http.StatusOK, Delay: time.Second},
			{AdminAuth: true, Path: "/tyk/keys/" + toBeRespectedKey, Code: http.StatusOK},
		}...)
	})
}

func TestInvalidateCache(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI()

	_, _ = ts.Run(t, []test.TestCase{
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
			_, _ = ts.Run(
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

	_, _ = ts.Run(
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

			_, _ = ts.Run(t, testCase)
		})
	}
}

func TestGroupResetHandler(t *testing.T) {
	ts := StartTest(nil)
	tryReloadCount := 100
	reloadCount := 0

	didSubscribe := make(chan bool, 1)
	didReload := make(chan bool, tryReloadCount)

	cacheStore := storage.RedisCluster{RedisController: ts.Gw.RedisController}
	cacheStore.Connect()

	// Test usually takes 0.05sec or so, timeout after 1s
	ctx, cancel := context.WithTimeout(ts.Gw.ctx, time.Second)
	defer cancel()

	// Using waitgroup to test cancellation
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		// Clean up resources on exit
		defer func() {
			close(didReload)
			close(didSubscribe)
			wg.Done()
		}()

		err := cacheStore.StartPubSubHandler(ctx, RedisPubSubChannel, func(v interface{}) {
			switch x := v.(type) {
			case *redis.Subscription:
				didSubscribe <- true
			case *redis.Message:
				notf := Notification{Gw: ts.Gw}

				err := json.Unmarshal([]byte(x.Payload), &notf)
				assert.NoError(t, err)

				if notf.Command == NoticeGroupReload {
					didReload <- true
					reloadCount++
				}
			}
		})

		select {
		case <-ctx.Done():
			// A cancelled context is expected at the end
			return
		default:
		}

		// Apart from a cancelled context, any error is
		// considered a fatal error.
		require.NoError(t, err)

	}()

	uri := "/tyk/reload/group"

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID = make(map[string]*APISpec)
	ts.Gw.apisMu.Unlock()

	ts.Gw.LoadSampleAPI(apiTestDef)

	// If we don't wait for the subscription to be done, we might do
	// the reload before pub/sub is in place to receive our message.
	<-didSubscribe

	// Do a loop of tryReloadCount reloads
	for try := 1; try <= tryReloadCount; try++ {
		req := ts.withAuth(TestReq(t, "GET", uri, nil))

		recorder := httptest.NewRecorder()
		ts.mainRouter().ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code, "Hot reload (group) failed")

		ts.Gw.apisMu.RLock()
		require.Len(t, ts.Gw.apisByID, 1, "Unexpected API count after hot reload (group) was triggered.")
		ts.Gw.apisMu.RUnlock()

		// We wait for the right notification (NoticeGroupReload), other
		// type of notifications may be received during tests, as this
		// is the cluster channel:
		select {
		case <-ctx.Done():
			t.Fatalf("Timeout waiting for reload signal, registered %d reloads", reloadCount)
		case ok := <-didReload:
			require.True(t, ok, "Reload failed (closed pubsub?)")
		}
	}

	// Close our *Test object, ensuring a cancelled context
	ts.Close()

	// Wait for our pubsub loop to exit
	wg.Wait()

	// Assert total reload count matches expected value
	assert.Equal(t, tryReloadCount, reloadCount, "Unexpected number of reloads registered from pubsub")
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
			Client:    test.NewClientLocal(),
			Path:      "/" + hp.path,
			Domain:    hp.host,
			Code:      200,
			BodyMatch: `"Url":"/` + hp.path + `"`,
		})
	}

	_, _ = ts.Run(t, testCases...)
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

			_, _ = ts.Run(t, testCase)
		})
	}
}

func TestHandleAddApi(t *testing.T) {
	testFs := afero.NewMemMapFs()

	ts := StartTest(nil)
	defer ts.Close()

	t.Run("should return error when api definition json is invalid", func(t *testing.T) {
		apiDefJson := []byte("{")
		req, err := http.NewRequest(http.MethodPost, "http://gateway", bytes.NewBuffer(apiDefJson))
		require.NoError(t, err)

		response, statusCode := ts.Gw.handleAddApi(req, testFs, false)
		errorResponse, ok := response.(apiStatusMessage)
		require.True(t, ok)

		assert.Equal(t, "Request malformed", errorResponse.Message)
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

		response, statusCode := ts.Gw.handleAddApi(req, testFs, false)
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

		response, statusCode := ts.Gw.handleAddApi(req, testFs, false)
		successResponse, ok := response.(apiModifyKeySuccess)
		require.True(t, ok)

		assert.Equal(t, "123", successResponse.Key)
		assert.Equal(t, "added", successResponse.Action)
		assert.Equal(t, http.StatusOK, statusCode)
	})

	t.Run("generate api id if not provided", func(t *testing.T) {
		apiDef := apidef.DummyAPI()
		apiDef.APIID = ""
		apiDefJson, err := json.Marshal(apiDef)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, "http://gateway", bytes.NewBuffer(apiDefJson))
		require.NoError(t, err)

		response, statusCode := ts.Gw.handleAddApi(req, testFs, false)
		successResponse, ok := response.(apiModifyKeySuccess)
		require.True(t, ok)

		assert.NotEmpty(t, successResponse.Key)
		assert.Equal(t, "added", successResponse.Action)
		assert.Equal(t, http.StatusOK, statusCode)
	})

}

func TestHandleUpdateApi(t *testing.T) {
	testFs := afero.NewMemMapFs()

	ts := StartTest(nil)
	defer ts.Close()

	oldAPIID := "old-api-id"

	oldAPI := BuildAPI(func(a *APISpec) {
		a.APIID = oldAPIID
		a.Name = "old api"
		a.Proxy.ListenPath = "/old-api/"
	})[0]
	// Create Old API
	_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/apis", Data: &oldAPI,
		BodyMatch: `"action":"added"`, Code: http.StatusOK})

	ts.Gw.DoReload()

	t.Run("should return error when api definition json is invalid", func(t *testing.T) {
		apiDefJson := []byte("{")
		req, err := http.NewRequest(http.MethodPut, "http://gateway", bytes.NewBuffer(apiDefJson))
		require.NoError(t, err)

		response, statusCode := ts.Gw.handleUpdateApi(oldAPIID, req, testFs, false)
		errorResponse, ok := response.(apiStatusMessage)
		require.True(t, ok)

		assert.Equal(t, "Request malformed", errorResponse.Message)
		assert.Equal(t, http.StatusBadRequest, statusCode)
	})

	t.Run("should return error when api ids are different", func(t *testing.T) {
		apiDef := apidef.DummyAPI()
		apiDef.APIID = "XXX"
		apiDefJson, err := json.Marshal(apiDef)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPut, "http://gateway", bytes.NewBuffer(apiDefJson))
		require.NoError(t, err)

		response, statusCode := ts.Gw.handleUpdateApi(oldAPIID, req, testFs, false)
		errorResponse, ok := response.(apiStatusMessage)
		require.True(t, ok)

		assert.Equal(t, "Request APIID does not match that in Definition! For Update operations these must match.", errorResponse.Message)
		assert.Equal(t, http.StatusBadRequest, statusCode)
	})

	t.Run("should return error when semantic validation fails", func(t *testing.T) {
		apiDef := apidef.DummyAPI()
		apiDef.APIID = oldAPIID
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

		req, err := http.NewRequest(http.MethodPut, "http://gateway", bytes.NewBuffer(apiDefJson))
		require.NoError(t, err)

		response, statusCode := ts.Gw.handleUpdateApi(oldAPIID, req, testFs, false)
		errorResponse, ok := response.(apiStatusMessage)
		require.True(t, ok)

		assert.Equal(t, "Validation of API Definition failed. Reason: duplicate data source names are not allowed.", errorResponse.Message)
		assert.Equal(t, http.StatusBadRequest, statusCode)
	})

	t.Run("should return success when no error occurs", func(t *testing.T) {
		apiDef := apidef.DummyAPI()
		apiDef.APIID = oldAPIID
		apiDefJson, err := json.Marshal(apiDef)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPut, "http://gateway", bytes.NewBuffer(apiDefJson))
		require.NoError(t, err)

		response, statusCode := ts.Gw.handleUpdateApi(oldAPIID, req, testFs, false)
		successResponse, ok := response.(apiModifyKeySuccess)
		require.True(t, ok)

		assert.Equal(t, oldAPIID, successResponse.Key)
		assert.Equal(t, "modified", successResponse.Action)
		assert.Equal(t, http.StatusOK, statusCode)
	})

	t.Run("API not found for non existing API", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPut, Path: "/tyk/apis/non-existing-api-id",
			BodyMatch: `"API not found"`, Code: http.StatusNotFound})
	})

}

func TestDeleteAPI(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("API not found for non existing API", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodDelete, Path: "/tyk/apis/non-existing-api-id",
			BodyMatch: `"API not found"`, Code: http.StatusNotFound})
	})
}

func TestOAS(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const (
		oldAPIID    = "old-api-id"
		oasAPIID    = "oas-api-id"
		oasBasePath = "/tyk/apis/oas"
	)

	oldAPI := BuildAPI(func(a *APISpec) {
		a.APIID = oldAPIID
		a.Name = "old api"
		a.Proxy.ListenPath = "/old-api/"
	})[0]

	tykExtension := oas.XTykAPIGateway{
		Info: oas.Info{
			Name: "oas api",
			ID:   oasAPIID,
			State: oas.State{
				Active: false,
			},
		},
		Upstream: oas.Upstream{
			URL: TestHttpAny,
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: "/oas-api/",
				Strip: false,
			},
		},
	}

	oasAPI := openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   "oas doc",
			Version: "1",
		},
		Paths: make(openapi3.Paths),
	}

	oasAPI.Extensions = map[string]interface{}{
		oas.ExtensionTykAPIGateway: tykExtension,
	}

	// Create Old API
	_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/apis", Data: &oldAPI,
		BodyMatch: `"action":"added"`, Code: http.StatusOK})

	// Create OAS API
	_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: oasBasePath, Data: &oasAPI,
		BodyMatch: `"action":"added"`, Code: http.StatusOK})

	ts.Gw.DoReload()

	oasAPI = testGetOASAPI(t, ts, oasAPIID, "oas api", "oas doc")
	assert.NotNil(t, oasAPI.Servers)

	createdOldAPI := testGetOldAPI(t, ts, oldAPIID, "old api")
	assert.NotNil(t, createdOldAPI)

	t.Run("OAS validation - should fail without x-tyk-api-gateway", func(t *testing.T) {
		oasAPI.Paths = make(openapi3.Paths)
		delete(oasAPI.Extensions, oas.ExtensionTykAPIGateway)
		_, _ = ts.Run(t, []test.TestCase{
			{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/apis/oas/", Data: &oasAPI,
				BodyMatch: apidef.ErrPayloadWithoutTykExtension.Error(), Code: http.StatusBadRequest},
		}...)

		oasAPI = testGetOASAPI(t, ts, oasAPIID, "oas api", "oas doc")
	})

	t.Run("OAS validation - should fail without paths", func(t *testing.T) {
		invalidOASAPI := oasAPI
		invalidOASAPI.Paths = nil
		_, _ = ts.Run(t, test.TestCase{
			AdminAuth: true,
			Method:    http.MethodPost,
			Path:      "/tyk/apis/oas/",
			Data:      &invalidOASAPI,
			BodyMatch: `"paths: Invalid type. Expected: object, given: null"`,
			Code:      http.StatusBadRequest,
		})
	})

	oasAPI.Paths = make(openapi3.Paths)

	t.Run("get old api in OAS format - should fail", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: oasBasePath + "/" + oldAPIID,
			BodyMatch: apidef.ErrOASGetForOldAPI.Error(), Code: http.StatusBadRequest})
	})

	t.Run("toggle isOAS - should override", func(t *testing.T) {
		oldAPIID2 := "old-api-id-2"
		oldAPI2 := BuildAPI(func(a *APISpec) {
			a.APIID = oldAPIID2
			a.Name = "old api 2"
			a.Proxy.ListenPath = "/old-api-2/"
			a.IsOAS = true
		})[0]

		_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/apis", Data: &oldAPI2,
			BodyMatch: `"action":"added"`, Code: http.StatusOK})

		ts.Gw.DoReload()

		createdOldAPI2 := testGetOldAPI(t, ts, oldAPIID2, oldAPI2.Name)
		assert.False(t, createdOldAPI2.IsOAS)
	})

	t.Run("update", func(t *testing.T) {
		t.Run("old api", func(t *testing.T) {

			apiID := oldAPIID

			t.Run("with old", func(t *testing.T) {

				oldAPIInOld := testGetOldAPI(t, ts, apiID, "old api")

				oldAPIInOld.Name = "old-updated old api"
				oldAPIInOld.Proxy.ListenPath = "/updated-old-api/"
				testUpdateAPI(t, ts, &oldAPIInOld, apiID, false)

				t.Run("get", func(t *testing.T) {

					t.Run("in old", func(t *testing.T) {
						testGetOldAPI(t, ts, apiID, "old-updated old api")
					})

					t.Run("in oas - should fail", func(t *testing.T) {
						_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: oasBasePath + "/" + oldAPIID,
							BodyMatch: apidef.ErrOASGetForOldAPI.Error(), Code: http.StatusBadRequest})
					})
				})

				// Reset
				testUpdateAPI(t, ts, &oldAPI, apiID, false)
			})

			t.Run("with oas - should fail", func(t *testing.T) {

				var oldAPIInOAS oas.OAS
				oldAPIInOAS.Fill(*oldAPI.APIDefinition)
				oldAPIInOAS.OpenAPI = "3.0.3"
				oldAPIInOAS.Info = &openapi3.Info{
					Title:   "old-api",
					Version: "1",
				}

				oldAPIInOAS.GetTykExtension().Info.Versioning = nil
				oldAPIInOAS.GetTykExtension().Server.GatewayTags = nil
				oldAPIInOAS.GetTykExtension().Upstream.MutualTLS = nil
				oldAPIInOAS.GetTykExtension().Upstream.CertificatePinning = nil

				oldAPIInOAS.Paths = make(openapi3.Paths)
				updatePath := "/tyk/apis/oas/" + apiID

				_, _ = ts.Run(t, []test.TestCase{
					{AdminAuth: true, Method: http.MethodPut, Path: updatePath, Data: &oldAPIInOAS,
						BodyMatch: apidef.ErrAPINotMigrated.Error(), Code: http.StatusBadRequest},
				}...)
			})

			// Reset
			testUpdateAPI(t, ts, &oldAPI, apiID, false)
		})

		t.Run("oas api", func(t *testing.T) {
			apiID := oasAPIID

			t.Run("with old", func(t *testing.T) {
				oasAPIInOld := testGetOldAPI(t, ts, apiID, "oas api")

				oasAPIInOld.Name = "old-updated oas api"

				t.Run("update oas API with old format - should fail", func(t *testing.T) {
					updatePath := "/tyk/apis/" + apiID

					_, _ = ts.Run(t, []test.TestCase{
						{AdminAuth: true, Method: http.MethodPut, Path: updatePath, Data: &oasAPIInOld,
							BodyMatch: apidef.ErrAPIMigrated.Error(), Code: http.StatusBadRequest},
					}...)
				})
			})

			t.Run("with oas and gateway tags enabled", func(t *testing.T) {
				oasAPIInOAS := testGetOASAPI(t, ts, apiID, "oas api", "oas doc")

				oasAPIInOAS.Extensions[oas.ExtensionTykAPIGateway] = oas.XTykAPIGateway{
					Info: oas.Info{Name: "oas-updated oas api", ID: apiID},
					Server: oas.Server{
						ListenPath: oas.ListenPath{
							Value: "/oas-updated",
						},
						GatewayTags: &oas.GatewayTags{
							Enabled: true,
							Tags:    []string{"rainbow"},
						},
					},
				}

				oasAPIInOAS.Paths = make(openapi3.Paths)

				oasAPIInOAS.Info.Title = "oas-updated oas doc"
				testUpdateAPI(t, ts, &oasAPIInOAS, apiID, true)

				t.Run("get", func(t *testing.T) {
					t.Run("in oas", func(t *testing.T) {
						testGetOASAPI(t, ts, apiID, "oas-updated oas api", "oas-updated oas doc")
					})

					t.Run("in old", func(t *testing.T) {
						testGetOldAPI(t, ts, apiID, "oas-updated oas api")
					})
				})

				// Reset
				testUpdateAPI(t, ts, &oasAPI, apiID, true)
			})

			t.Run("with oas", func(t *testing.T) {
				oasAPIInOAS := testGetOASAPI(t, ts, apiID, "oas api", "oas doc")

				oasAPIInOAS.Extensions[oas.ExtensionTykAPIGateway] = oas.XTykAPIGateway{
					Info: oas.Info{Name: "oas-updated oas api", ID: apiID},
					Server: oas.Server{
						ListenPath: oas.ListenPath{
							Value: "/oas-updated",
						},
					},
				}

				oasAPIInOAS.Paths = make(openapi3.Paths)

				oasAPIInOAS.Info.Title = "oas-updated oas doc"
				testUpdateAPI(t, ts, &oasAPIInOAS, apiID, true)

				t.Run("get", func(t *testing.T) {
					t.Run("in oas", func(t *testing.T) {
						testGetOASAPI(t, ts, apiID, "oas-updated oas api", "oas-updated oas doc")
					})

					t.Run("in old", func(t *testing.T) {
						testGetOldAPI(t, ts, apiID, "oas-updated oas api")
					})
				})

				// Reset
				testUpdateAPI(t, ts, &oasAPI, apiID, true)
			})

			t.Run("OAS validation", func(t *testing.T) {
				oasAPIInOAS := testGetOASAPI(t, ts, apiID, "oas api", "oas doc")

				oasAPIInOAS.Info.Title = "oas-updated oas doc"

				oasAPIInOAS.Paths = nil

				updatePath := fmt.Sprintf("/tyk/apis/oas/%s", apiID)

				_, _ = ts.Run(t, []test.TestCase{
					{AdminAuth: true, Method: http.MethodPut, Path: updatePath, Data: &oasAPIInOAS,
						BodyMatch: `"paths: Invalid type. Expected: object, given: null"`, Code: http.StatusBadRequest},
				}...)
			})
		})

		t.Run("oas api/export", func(t *testing.T) {
			apiID := oasAPIID
			oasExportPath := "/tyk/apis/oas/export"
			matchHeaders := map[string]string{
				"Content-Type": "application/octet-stream",
			}

			t.Run("with old", func(t *testing.T) {

				t.Run("get", func(t *testing.T) {
					_, _ = ts.Run(t, []test.TestCase{
						{AdminAuth: true, Method: http.MethodGet, Path: oasExportPath, BodyMatch: `\"x-tyk-api-gateway\":`,
							Code: http.StatusOK, HeadersMatch: matchHeaders},
						{AdminAuth: true, Method: http.MethodGet, Path: oasBasePath + "/" + oldAPIID + "/export",
							BodyMatch: apidef.ErrOASGetForOldAPI.Error(),
							Code:      http.StatusBadRequest},
					}...)
				})
				t.Run("get scope public", func(t *testing.T) {
					_, _ = ts.Run(t, []test.TestCase{
						{AdminAuth: true, Method: http.MethodGet, Path: oasExportPath + "?mode=public", BodyMatch: `.*components`,
							BodyNotMatch: ".*\"x-tyk-api-gateway\":", Code: http.StatusOK, HeadersMatch: matchHeaders},
						{AdminAuth: true, Method: http.MethodGet, Path: oasBasePath + "/" + oldAPIID + "/export?mode=public",
							BodyMatch: apidef.ErrOASGetForOldAPI.Error(), Code: http.StatusBadRequest},
					}...)
				})

				// Reset
				testUpdateAPI(t, ts, &oasAPI, apiID, true)
			})

			t.Run("with oas", func(t *testing.T) {
				const oasExportPath = "/tyk/apis/oas/export"

				t.Run("get", func(t *testing.T) {
					_, _ = ts.Run(t, []test.TestCase{
						{AdminAuth: true, Method: http.MethodGet, Path: oasExportPath, BodyMatch: `\"x-tyk-api-gateway\":`, Code: http.StatusOK, HeadersMatch: matchHeaders},
						{AdminAuth: true, Method: http.MethodGet, Path: oasBasePath + "/" + oasAPIID + "/export", BodyMatch: `\"x-tyk-api-gateway\":`, Code: http.StatusOK, HeadersMatch: matchHeaders},
					}...)
				})
				t.Run("get scope public", func(t *testing.T) {
					_, _ = ts.Run(t, []test.TestCase{
						{AdminAuth: true, Method: http.MethodGet, Path: oasBasePath + "/" + oasAPIID + "/export?mode=public", BodyMatch: `components`, BodyNotMatch: ".*\"x-tyk-api-gateway\":", Code: http.StatusOK, HeadersMatch: matchHeaders},
					}...)
				})
			})

			t.Run("not found", func(t *testing.T) {

				t.Run("get", func(t *testing.T) {
					_, _ = ts.Run(t, []test.TestCase{
						{AdminAuth: true, Method: http.MethodGet, Path: oasExportPath + "/invalidID/export", BodyNotMatch: ".*\"components\":", Code: http.StatusNotFound, HeadersNotMatch: matchHeaders},
					}...)
				})

				// Reset
				testUpdateAPI(t, ts, &oasAPI, apiID, true)
			})
		})
	})

	t.Run("patch", func(t *testing.T) {
		apiID := oasAPIID

		// copy OAS API, we need to manipulate tyk extension here
		copyOAS := func(oasAPI openapi3.T) oas.OAS {
			apiInOAS := oas.OAS{T: oasAPI}
			oasExt := oasAPI.ExtensionProps.Extensions
			copyExt := make(map[string]interface{})
			for k, v := range oasExt {
				copyExt[k] = v
			}
			apiInOAS.T.ExtensionProps.Extensions = copyExt
			return apiInOAS
		}

		fillPaths := func(oasAPI *oas.OAS) {
			oasAPI.Paths = openapi3.Paths{
				"/pets": {
					Get: &openapi3.Operation{
						Summary: "get pets",
						Responses: openapi3.Responses{
							"200": {
								Value: &openapi3.Response{
									Description: getStrPointer("200 response"),
									Content: openapi3.Content{
										"application/json": {
											Schema: &openapi3.SchemaRef{
												Value: &openapi3.Schema{
													Properties: openapi3.Schemas{
														"value": &openapi3.SchemaRef{
															Value: &openapi3.Schema{Type: openapi3.TypeBoolean},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
					Post: &openapi3.Operation{
						Responses: openapi3.Responses{
							"200": {
								Value: &openapi3.Response{
									Description: getStrPointer("200 response"),
									Content: openapi3.Content{
										"application/json": {
											Schema: &openapi3.SchemaRef{
												Value: &openapi3.Schema{
													Properties: openapi3.Schemas{
														"added": &openapi3.SchemaRef{
															Value: &openapi3.Schema{Type: openapi3.TypeBoolean},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
		}

		fillReqBody := func(oasDef *oas.OAS, path, method string) {
			pathItem := oasDef.Paths.Find(path)
			oasOperation := pathItem.GetOperation(method)
			reqBody := openapi3.NewRequestBody()
			reqBody.Description = "JSON req body"
			valueSchema := openapi3.NewSchema()
			valueSchema.Properties = openapi3.Schemas{
				"value": {
					Value: &openapi3.Schema{
						Type: openapi3.TypeBoolean,
					},
				},
			}
			content := openapi3.NewContentWithSchema(valueSchema, []string{"application/json"})
			reqBody.Content = content
			oasOperation.RequestBody = &openapi3.RequestBodyRef{Value: reqBody}
		}

		t.Run("when tyk extension is provided and no params are provided - act like PUT", func(t *testing.T) {
			apiInOAS := copyOAS(oasAPI)
			fillPaths(&apiInOAS)
			tykExt := apiInOAS.GetTykExtension()
			tykExt.Info.Name = "patched-oas-api"

			apiInOAS.T.Info.Title = "patched-oas-doc"
			testPatchOAS(t, ts, apiInOAS, nil, apiID)
			patchedOASObj := testGetOASAPI(t, ts, apiID, tykExt.Info.Name, apiInOAS.T.Info.Title)
			o := oas.OAS{T: patchedOASObj}
			assert.Equal(t, tykExt, o.GetTykExtension())

			// Reset
			testUpdateAPI(t, ts, &oasAPI, apiID, true)
		})

		t.Run("when tyk extension and parameters are not provided - update OAS part only", func(t *testing.T) {
			apiInOAS := copyOAS(oasAPI)
			fillPaths(&apiInOAS)

			tykExt := apiInOAS.GetTykExtension()
			delete(apiInOAS.ExtensionProps.Extensions, oas.ExtensionTykAPIGateway)

			apiInOAS.T.Info.Title = "patched-oas-doc"
			testPatchOAS(t, ts, apiInOAS, nil, apiID)
			patchedOASObj := testGetOASAPI(t, ts, apiID, tykExt.Info.Name, apiInOAS.T.Info.Title)
			o := oas.OAS{T: patchedOASObj}

			assert.Equal(t, tykExt, o.GetTykExtension())

			// Reset
			testUpdateAPI(t, ts, &oasAPI, oasAPIID, true)
		})

		t.Run("when params are provided and no tyk extension in request - override values in existing API", func(t *testing.T) {
			apiInOAS := copyOAS(oasAPI)
			fillPaths(&apiInOAS)
			fillReqBody(&apiInOAS, "/pets", http.MethodPost)

			expectedTykExt := apiInOAS.GetTykExtension()
			delete(apiInOAS.ExtensionProps.Extensions, oas.ExtensionTykAPIGateway)

			listenPath, upstreamURL, customDomain := "/listen-api/", "https://new-upstream.org", "custom-upstream.com"

			params := map[string]string{
				"listenPath":      listenPath,
				"upstreamURL":     upstreamURL,
				"customDomain":    customDomain,
				"allowList":       "true",
				"validateRequest": "true",
			}

			expectedTykExt.Server.ListenPath.Value = listenPath
			expectedTykExt.Upstream.URL = upstreamURL
			expectedTykExt.Server.CustomDomain = &oas.Domain{
				Enabled: true,
				Name:    customDomain,
			}

			expectedTykExt.Middleware = &oas.Middleware{
				Operations: oas.Operations{
					"petsGET": {
						Allow: &oas.Allowance{
							Enabled: true,
						},
					},
					"petsPOST": {
						Allow: &oas.Allowance{
							Enabled: true,
						},
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: http.StatusUnprocessableEntity,
						},
					},
				},
			}

			testPatchOAS(t, ts, apiInOAS, params, apiID)
			patchedOASObj := testGetOASAPI(t, ts, apiID, expectedTykExt.Info.Name, apiInOAS.T.Info.Title)
			o := oas.OAS{T: patchedOASObj}

			assert.EqualValues(t, expectedTykExt, o.GetTykExtension())

			// Reset
			testUpdateAPI(t, ts, &oasAPI, oasAPIID, true)
		})

		t.Run("when param are provided and tyk extension in request - override values (if any) in request", func(t *testing.T) {
			apiInOAS := copyOAS(oasAPI)
			fillPaths(&apiInOAS)
			fillReqBody(&apiInOAS, "/pets", http.MethodPost)

			upstreamURL, customDomain := "https://new-upstream.org", "custom-upstream.com"

			params := map[string]string{
				"upstreamURL":     upstreamURL,
				"customDomain":    customDomain,
				"allowList":       "false",
				"validateRequest": "false",
			}

			expectedTykExt := *apiInOAS.GetTykExtension()

			expectedTykExt.Upstream.URL = upstreamURL
			expectedTykExt.Server.CustomDomain = &oas.Domain{
				Enabled: true,
				Name:    customDomain,
			}
			expectedTykExt.Middleware = &oas.Middleware{
				Operations: oas.Operations{
					"petsGET": {
						Allow: &oas.Allowance{
							Enabled: false,
						},
					},
					"petsPOST": {
						Allow: &oas.Allowance{
							Enabled: false,
						},
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           false,
							ErrorResponseCode: http.StatusUnprocessableEntity,
						},
					},
				},
			}

			testPatchOAS(t, ts, apiInOAS, params, apiID)
			patchedOASObj := testGetOASAPI(t, ts, apiID, expectedTykExt.Info.Name, apiInOAS.T.Info.Title)
			o := oas.OAS{T: patchedOASObj}

			assert.EqualValues(t, expectedTykExt, *o.GetTykExtension())

			// Reset
			testUpdateAPI(t, ts, &oasAPI, oasAPIID, true)
		})

		t.Run("retain old OAS servers", func(t *testing.T) {
			t.Run("should retain first entry in existing API", func(t *testing.T) {
				apiInOAS := copyOAS(oasAPI)
				fillPaths(&apiInOAS)

				tykExt := apiInOAS.GetTykExtension()
				delete(apiInOAS.ExtensionProps.Extensions, oas.ExtensionTykAPIGateway)

				apiInOAS.T.Info.Title = "patched-oas-doc"

				serverURL := "https://upstream.org/api"
				apiInOAS.Servers = openapi3.Servers{
					{
						URL: serverURL,
					},
				}

				gwServerURL := oasAPI.Servers[0].URL

				testPatchOAS(t, ts, apiInOAS, nil, apiID)
				patchedOASObj := testGetOASAPI(t, ts, apiID, tykExt.Info.Name, apiInOAS.T.Info.Title)

				assert.EqualValues(t, gwServerURL, patchedOASObj.Servers[0].URL)
				assert.Equal(t, serverURL, patchedOASObj.Servers[1].URL)
				// Reset
				testUpdateAPI(t, ts, &oasAPI, oasAPIID, true)
			})

			t.Run("do not modify if first server is same as that of gw", func(t *testing.T) {
				apiInOAS := copyOAS(oasAPI)
				fillPaths(&apiInOAS)

				tykExt := apiInOAS.GetTykExtension()
				delete(apiInOAS.ExtensionProps.Extensions, oas.ExtensionTykAPIGateway)

				apiInOAS.T.Info.Title = "patched-oas-doc"

				serverURL1 := oasAPI.Servers[0].URL
				serverURL2 := "https://upstream.org/api"
				serverURL3 := "https://upstream.com/api"
				apiInOAS.Servers = openapi3.Servers{
					{
						URL: serverURL1,
					},
					{
						URL: serverURL2,
					},
					{
						URL: serverURL3,
					},
				}

				testPatchOAS(t, ts, apiInOAS, nil, apiID)
				patchedOASObj := testGetOASAPI(t, ts, apiID, tykExt.Info.Name, apiInOAS.T.Info.Title)

				assert.EqualValues(t, serverURL1, patchedOASObj.Servers[0].URL)
				assert.Equal(t, serverURL2, patchedOASObj.Servers[1].URL)
				assert.Equal(t, serverURL3, patchedOASObj.Servers[2].URL)
				// Reset
				testUpdateAPI(t, ts, &oasAPI, oasAPIID, true)
			})
		})

		t.Run("error on invalid upstreamURL", func(t *testing.T) {
			apiInOAS := copyOAS(oasAPI)
			fillPaths(&apiInOAS)
			delete(apiInOAS.ExtensionProps.Extensions, oas.ExtensionTykAPIGateway)

			upstreamURL := "new-upstream.org"

			params := map[string]string{
				"upstreamURL": upstreamURL,
			}

			patchPath := fmt.Sprintf("/tyk/apis/oas/%s", apiID)

			_, _ = ts.Run(t, []test.TestCase{
				{AdminAuth: true, Method: http.MethodPatch, Path: patchPath, Data: &apiInOAS,
					QueryParams: params, BodyMatch: `"message":"invalid upstream URL"`, Code: http.StatusBadRequest},
			}...)
		})

		t.Run("request validation", func(t *testing.T) {
			patchPath := fmt.Sprintf("/tyk/apis/oas/%s", apiID)

			t.Run("empty apiID", func(t *testing.T) {
				apiInOAS := copyOAS(oasAPI)
				fillPaths(&apiInOAS)
				delete(apiInOAS.ExtensionProps.Extensions, oas.ExtensionTykAPIGateway)

				patchPath := fmt.Sprintf("/tyk/apis/oas/%s", " ")

				_, _ = ts.Run(t, []test.TestCase{
					{AdminAuth: true, Method: http.MethodPatch, Path: patchPath, Data: &apiInOAS,
						BodyMatch: `"message":"Must specify an apiID to patch"`, Code: http.StatusBadRequest},
				}...)
			})

			t.Run("malformed body", func(t *testing.T) {
				apiInOAS := copyOAS(oasAPI)
				fillPaths(&apiInOAS)
				delete(apiInOAS.ExtensionProps.Extensions, oas.ExtensionTykAPIGateway)

				_, _ = ts.Run(t, []test.TestCase{
					{AdminAuth: true, Method: http.MethodPatch, Path: patchPath, Data: `oas-body`,
						BodyMatch: `"message":"request malformed"`, Code: http.StatusBadRequest},
				}...)
			})

			t.Run("error when APIID doesn't exist in gw", func(t *testing.T) {
				apiInOAS := copyOAS(oasAPI)
				fillPaths(&apiInOAS)

				delete(apiInOAS.ExtensionProps.Extensions, oas.ExtensionTykAPIGateway)

				nonExistingAPIID := "non-existing-api-id"
				patchPath := fmt.Sprintf("/tyk/apis/oas/%s", nonExistingAPIID)

				_, _ = ts.Run(t, []test.TestCase{
					{AdminAuth: true, Method: http.MethodPatch, Path: patchPath, Data: &apiInOAS,
						BodyMatchFunc: func(body []byte) bool {
							resp := apiStatusMessage{}
							err := json.Unmarshal(body, &resp)
							if err != nil {
								return false
							}
							return apidef.ErrAPINotFound.Error() == resp.Message
						},
						Code: http.StatusNotFound},
				}...)
			})

			t.Run("when dashboard app config set to true", func(t *testing.T) {
				apiInOAS := copyOAS(oasAPI)
				fillPaths(&apiInOAS)

				conf := ts.Gw.GetConfig()
				conf.UseDBAppConfigs = true
				ts.Gw.SetConfig(conf)

				defer func() {
					conf.UseDBAppConfigs = false
					ts.Gw.SetConfig(conf)
				}()

				delete(apiInOAS.ExtensionProps.Extensions, oas.ExtensionTykAPIGateway)

				_, _ = ts.Run(t, []test.TestCase{
					{AdminAuth: true, Method: http.MethodPatch, Path: patchPath, Data: &apiInOAS,
						BodyMatch: "Due to enabled use_db_app_configs, please use the Dashboard API",
						Code:      http.StatusInternalServerError},
				}...)
			})

			t.Run("fail when non OAS API tried to patch", func(t *testing.T) {
				oldAPI.OAS.Fill(*oldAPI.APIDefinition)
				apiInOAS := oldAPI.OAS
				fillPaths(&apiInOAS)
				tykExt := apiInOAS.GetTykExtension()
				tykExt.Info.Name = "patched-oas-api"
				tykExt.Info.Versioning.Default = "default"
				tykExt.Info.Versioning.Versions = []oas.VersionToID{}
				tykExt.Server.GatewayTags = nil
				tykExt.Upstream.MutualTLS = nil
				tykExt.Upstream.CertificatePinning = nil
				apiInOAS.T.Info = &openapi3.Info{Title: "patched-oas-doc", Version: "1"}
				apiInOAS.OpenAPI = "3.0.3"

				patchPath := fmt.Sprintf("/tyk/apis/oas/%s", oldAPI.APIID)
				_, _ = ts.Run(t, []test.TestCase{
					{AdminAuth: true, Method: http.MethodPatch, Path: patchPath, Data: &apiInOAS,
						BodyMatch: apidef.ErrAPINotMigrated.Error(),
						Code:      http.StatusBadRequest},
				}...)
			})

		})

		t.Run("OAS validation", func(t *testing.T) {
			apiInOAS := copyOAS(oasAPI)
			fillPaths(&apiInOAS)

			delete(apiInOAS.T.ExtensionProps.Extensions, oas.ExtensionTykAPIGateway)
			apiInOAS.Paths = nil

			patchPath := fmt.Sprintf("/tyk/apis/oas/%s", apiID)

			_, _ = ts.Run(t, []test.TestCase{
				{AdminAuth: true, Method: http.MethodPatch, Path: patchPath, Data: &apiInOAS,
					BodyMatch: `"paths: Invalid type. Expected: object, given: null"`, Code: http.StatusBadRequest},
			}...)
		})

	})

	t.Run("delete", func(t *testing.T) {
		basePath := "/tyk/apis/"
		t.Run("oas", func(t *testing.T) {
			listenPath := "/" + strings.TrimSuffix(oasAPIID, "-id") + "/"
			defOASFilePath := filepath.Join(ts.Gw.GetConfig().AppPath, oasAPIID+"-oas.json")
			defFilePath := filepath.Join(ts.Gw.GetConfig().AppPath, oasAPIID+".json")

			_, err := os.Stat(defFilePath)
			assert.NoError(t, err)

			_, err = os.Stat(defOASFilePath)
			assert.NoError(t, err)

			path := basePath + oasAPIID
			oasPath := oasBasePath + "/" + oasAPIID

			_, _ = ts.Run(t, []test.TestCase{
				{Method: http.MethodGet, Path: listenPath, Code: http.StatusOK},
				{AdminAuth: true, Method: http.MethodGet, Path: path, BodyNotMatch: "components", Code: http.StatusOK},
				{AdminAuth: true, Method: http.MethodGet, Path: oasPath, BodyMatch: `components`, Code: http.StatusOK},
				{AdminAuth: true, Method: http.MethodDelete, Path: path, BodyMatch: `"action":"deleted"`, Code: http.StatusOK},
			}...)

			ts.Gw.DoReload()

			_, _ = ts.Run(t, []test.TestCase{
				{AdminAuth: true, Method: http.MethodGet, Path: oasPath,
					BodyMatch: `"message":"API not found"`, Code: http.StatusNotFound},
				{AdminAuth: true, Method: http.MethodGet, Path: path,
					BodyMatch: `"message":"API not found"`, Code: http.StatusNotFound},
				{Method: http.MethodGet, Path: listenPath, Code: http.StatusNotFound},
			}...)

			_, err = os.Stat(defFilePath)
			assert.Error(t, err)

			_, err = os.Stat(defOASFilePath)
			assert.Error(t, err)
		})

		t.Run("old api", func(t *testing.T) {
			listenPath := "/" + strings.TrimSuffix(oldAPIID, "-id") + "/"
			defOASFilePath := filepath.Join(ts.Gw.GetConfig().AppPath, oldAPIID+"-oas.json")
			defFilePath := filepath.Join(ts.Gw.GetConfig().AppPath, oldAPIID+".json")

			_, err := os.Stat(defFilePath)
			assert.NoError(t, err)

			// assert no OAS spec file saved when not in OAS mode
			_, err = os.Stat(defOASFilePath)
			assert.Error(t, err)

			path := basePath + oldAPIID
			oasPath := oasBasePath + "/" + oldAPIID

			_, _ = ts.Run(t, []test.TestCase{
				{Method: http.MethodGet, Path: listenPath, Code: http.StatusOK},
				{AdminAuth: true, Method: http.MethodGet, Path: path, BodyNotMatch: "components", Code: http.StatusOK},
				{AdminAuth: true, Method: http.MethodGet, Path: oasPath,
					BodyMatch: apidef.ErrOASGetForOldAPI.Error(), Code: http.StatusBadRequest},
				{AdminAuth: true, Method: http.MethodDelete, Path: path, BodyMatch: `"action":"deleted"`, Code: http.StatusOK},
			}...)

			ts.Gw.DoReload()

			_, _ = ts.Run(t, []test.TestCase{
				{AdminAuth: true, Method: http.MethodGet, Path: oasPath,
					BodyMatch: `"message":"API not found"`, Code: http.StatusNotFound},
				{AdminAuth: true, Method: http.MethodGet, Path: path,
					BodyMatch: `"message":"API not found"`, Code: http.StatusNotFound},
				{Method: http.MethodGet, Path: listenPath, Code: http.StatusNotFound},
			}...)

			_, err = os.Stat(defFilePath)
			assert.Error(t, err)
		})
	})

	t.Run("import/OAS", func(t *testing.T) {
		configParams := func(ext oas.TykExtensionConfigParams) map[string]string {
			params := map[string]string{}
			if ext.UpstreamURL != "" {
				params["upstreamURL"] = ext.UpstreamURL
			}

			if ext.ListenPath != "" {
				params["listenPath"] = ext.ListenPath
			}

			if ext.CustomDomain != "" {
				params["customDomain"] = ext.CustomDomain
			}

			if ext.ApiID != "" {
				params["apiID"] = ext.ApiID
			}

			return params
		}

		ext := oas.TykExtensionConfigParams{
			CustomDomain: "example.com",
			UpstreamURL:  TestHttpAny,
			ListenPath:   "/listen-path",
			ApiID:        oasAPIID,
		}

		oasCopy := func(withTykExt bool, setter func(t *openapi3.T)) []byte {
			toOas := oas.OAS{T: openapi3.T{
				OpenAPI: "3.0.3",
				Info: &openapi3.Info{
					Title:   "example oas doc",
					Version: "1",
				},
				Paths: openapi3.Paths{},
				Servers: openapi3.Servers{
					&openapi3.Server{
						URL:         "http://upstream.example.com",
						Description: "main server upstream",
					},
				},
			}}
			if withTykExt {
				toOas.SetTykExtension(&oas.XTykAPIGateway{
					Info: oas.Info{
						Name: "oas api",
						ID:   oasAPIID,
						State: oas.State{
							Active: false,
						},
					},
					Upstream: oas.Upstream{
						URL: TestHttpAny,
					},
					Server: oas.Server{
						ListenPath: oas.ListenPath{
							Value: "/oas-api/",
							Strip: false,
						},
					},
				})
			}
			if setter != nil {
				setter(&toOas.T)
			}
			data, _ := toOas.MarshalJSON()
			return data
		}

		t.Run("error with tyk extension", func(t *testing.T) {
			testImportOAS(t, ts, test.TestCase{
				Code: http.StatusBadRequest, BodyMatch: apidef.ErrImportWithTykExtension.Error(), Data: oasCopy(true, nil), AdminAuth: true,
			})
		})

		t.Run("success without tyk extension", func(t *testing.T) {
			params := configParams(ext)
			importedOASAPIID := testImportOAS(t, ts, test.TestCase{
				Code: http.StatusOK, QueryParams: params, BodyMatch: "added", Data: oasCopy(false, nil), AdminAuth: true,
			})

			importT := testGetOASAPI(t, ts, importedOASAPIID, "example oas doc", "example oas doc")
			importedOAS := oas.OAS{T: importT}
			assert.True(t, importedOAS.GetTykExtension().Server.ListenPath.Strip)
		})

		t.Run("missing paths from OAS", func(t *testing.T) {
			params := configParams(ext)
			data := oasCopy(false, func(t *openapi3.T) {
				t.Paths = nil
			})
			testImportOAS(t, ts, test.TestCase{Code: http.StatusBadRequest, Data: data, AdminAuth: true, QueryParams: params})
		})

		t.Run("malformed upstream URL", func(t *testing.T) {
			newParam := ext
			newParam.UpstreamURL = "upstream.example.com"
			params := configParams(newParam)
			_ = testImportOAS(t, ts, test.TestCase{QueryParams: params,
				Code: http.StatusBadRequest, Data: oasCopy(false, nil), AdminAuth: true, BodyMatch: "invalid upstream URL",
			})
		})

		t.Run("missing upstream URL", func(t *testing.T) {
			oasAPI := oasCopy(false, func(t *openapi3.T) {
				t.Servers = openapi3.Servers{}
			})
			_ = testImportOAS(t, ts, test.TestCase{Code: http.StatusBadRequest, Data: oasAPI, AdminAuth: true, BodyMatch: "servers object is empty in OAS"})
		})

		t.Run("success without config query params, no tyk ext", func(t *testing.T) {
			importedOASAPIID := testImportOAS(t, ts, test.TestCase{Code: http.StatusOK, Data: oasCopy(false, nil), AdminAuth: true})

			importT := testGetOASAPI(t, ts, importedOASAPIID, "example oas doc", "example oas doc")
			importedOAS := oas.OAS{T: importT}
			assert.True(t, importedOAS.GetTykExtension().Server.ListenPath.Strip)
		})

		t.Run("block when dashboard app config set to true", func(t *testing.T) {
			apiInOAS := oasCopy(false, nil)

			conf := ts.Gw.GetConfig()
			conf.UseDBAppConfigs = true
			ts.Gw.SetConfig(conf)

			defer func() {
				conf.UseDBAppConfigs = false
				ts.Gw.SetConfig(conf)
			}()

			_, _ = ts.Run(t, []test.TestCase{
				{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/apis/oas/import", Data: &apiInOAS,
					BodyMatch: "Due to enabled use_db_app_configs, please use the Dashboard API",
					Code:      http.StatusInternalServerError},
			}...)
		})

	})
}

func testUpdateAPI(t *testing.T, ts *Test, api interface{}, apiID string, oasTyped bool) {
	t.Helper()
	updatePath := "/tyk/apis/"
	if oasTyped {
		updatePath += "oas/"
	}
	updatePath += apiID

	_, _ = ts.Run(t, []test.TestCase{
		{AdminAuth: true, Method: http.MethodPut, Path: updatePath, Data: &api,
			BodyMatch: `"action":"modified"`, Code: http.StatusOK},
	}...)

	ts.Gw.DoReload()
}

func testGetOASAPI(t *testing.T, d *Test, id, name, title string) (oasDoc openapi3.T) {
	t.Helper()
	getPath := "/tyk/apis/oas/" + id
	bodyMatch := fmt.Sprintf(`{.*"info":{"title":"%s".*"x-tyk-api-gateway":{"info":{.*"name":"%s"`, title, name)

	resp, _ := d.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: getPath,
		BodyMatch: bodyMatch, Code: http.StatusOK})

	respInBytes, _ := ioutil.ReadAll(resp.Body)
	_ = json.Unmarshal(respInBytes, &oasDoc)

	return oasDoc
}

func testGetOldAPI(t *testing.T, d *Test, id, name string) (oldAPI apidef.APIDefinition) {
	t.Helper()

	getPath := "/tyk/apis/" + id
	bodyMatch := fmt.Sprintf(`"name":"%s".*`, name)

	resp, _ := d.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: getPath,
		BodyMatch: bodyMatch, BodyNotMatch: "components", Code: http.StatusOK})

	respInBytes, _ := ioutil.ReadAll(resp.Body)
	_ = json.Unmarshal(respInBytes, &oldAPI)

	return oldAPI
}

func testPatchOAS(t *testing.T, ts *Test, api oas.OAS, params map[string]string, apiID string) {
	patchPath := fmt.Sprintf("/tyk/apis/oas/%s", apiID)

	_, _ = ts.Run(t, []test.TestCase{
		{AdminAuth: true, Method: http.MethodPatch, Path: patchPath, Data: &api,
			QueryParams: params, BodyMatch: `"action":"modified"`, Code: http.StatusOK},
	}...)

	ts.Gw.DoReload()
}

func testImportOAS(t *testing.T, ts *Test, testCase test.TestCase) string {
	var importResp apiModifyKeySuccess

	testCase.Path = "/tyk/apis/oas/import"
	testCase.Method = http.MethodPost
	resp, _ := ts.Run(t, testCase)

	respInBytes, _ := ioutil.ReadAll(resp.Body)
	_ = json.Unmarshal(respInBytes, &importResp)

	ts.Gw.DoReload()

	return importResp.Key
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
