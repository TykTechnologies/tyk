package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/garyburd/redigo/redis"
	uuid "github.com/satori/go.uuid"

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

func loadSampleAPI(t *testing.T, def string) {
	spec := CreateSpecTest(t, def)
	loadApps([]*APISpec{spec})
}

type testAPIDefinition struct {
	apidef.APIDefinition
	ID string `json:"id"`
}

func TestHealthCheckEndpoint(t *testing.T) {
	globalConf := config.Global()
	globalConf.HealthCheck.EnableHealthChecks = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI()

	ts.Run(t, []test.TestCase{
		{Path: "/tyk/health/?api_id=test", AdminAuth: true, Code: 200},
		{Path: "/tyk/health/?api_id=unknown", AdminAuth: true, Code: 404, BodyMatch: `"message":"API ID not found"`},
	}...)
}

func TestApiHandlerPostDupPath(t *testing.T) {
	type testCase struct {
		APIID, ListenPath string
	}

	assertListenPaths := func(tests []testCase) {
		for _, tc := range tests {
			s := getApiSpec(tc.APIID)
			if want, got := tc.ListenPath, s.Proxy.ListenPath; want != got {
				t.Errorf("API spec %s want path %s, got %s", "2", want, got)
			}
		}
	}

	t.Run("Sequentieal order", func(t *testing.T) {
		// Load initial API
		BuildAndLoadAPI(
			func(spec *APISpec) { spec.APIID = "1" },
		)

		BuildAndLoadAPI(
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
		BuildAndLoadAPI(
			func(spec *APISpec) { spec.APIID = "2" },
			func(spec *APISpec) { spec.APIID = "3" },
		)

		assertListenPaths([]testCase{
			{"2", "/sample-2"},
			{"3", "/sample-3"},
		})
	})

	t.Run("Restore original order", func(t *testing.T) {
		BuildAndLoadAPI(
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
	ts := StartTest()
	defer ts.Close()

	defer ResetTestConfig()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Auth.UseParam = true
	})

	// Access right not specified
	masterKey := CreateStandardSession()
	masterKeyJSON, _ := json.Marshal(masterKey)

	// with access
	withAccess := CreateStandardSession()
	withAccess.AccessRights = map[string]user.AccessDefinition{"test": {
		APIID: "test", Versions: []string{"v1"},
	}}
	withAccessJSON, _ := json.Marshal(withAccess)

	// with policy
	policiesMu.Lock()
	policiesByID["abc_policy"] = user.Policy{
		Active:           true,
		QuotaMax:         5,
		QuotaRenewalRate: 300,
		AccessRights: map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}},
		OrgID: "default",
	}
	policiesMu.Unlock()
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

		FallbackKeySesionManager.Store().DeleteAllKeys()
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

		globalConf := config.Global()
		globalConf.HashKeyFunction = ""
		config.SetGlobal(globalConf)
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

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.Auth.UseParam = true
		spec.OrgID = "default"
	})

	pID := CreatePolicy(func(p *user.Policy) {
		p.Partitions.RateLimit = true
		p.Tags = []string{"p1-tag"}
	})

	pID2 := CreatePolicy(func(p *user.Policy) {
		p.Partitions.Quota = true
		p.Tags = []string{"p2-tag"}
	})

	session, key := ts.CreateSession(func(s *user.SessionState) {
		s.ApplyPolicies = []string{pID}
		s.Tags = []string{"key-tag1", "key-tag2"}
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

		sessionState, found := FallbackKeySesionManager.SessionDetail(key, false)
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

		sessionState, found := FallbackKeySesionManager.SessionDetail(key, false)
		if !found || sessionState.AccessRights[testAPIID].APIID != testAPIID || len(sessionState.ApplyPolicies) != 0 {
			t.Fatal("Removing policy from the list failed")
		}
	})

	t.Run("Tag on key level", func(t *testing.T) {
		assert := func(session *user.SessionState, expected []string) {
			sessionData, _ := json.Marshal(session)
			path := fmt.Sprintf("/tyk/keys/%s", key)

			_, _ = ts.Run(t, []test.TestCase{
				{Method: http.MethodPut, Path: path, Data: sessionData, AdminAuth: true, Code: 200},
			}...)

			sessionState, found := FallbackKeySesionManager.SessionDetail(key, false)

			sort.Strings(sessionState.Tags)
			sort.Strings(expected)

			if !found || !reflect.DeepEqual(expected, sessionState.Tags) {
				t.Fatalf("Expected %v, returned %v", expected, sessionState.Tags)
			}
		}

		t.Run("Add", func(t *testing.T) {
			expected := []string{"p1-tag", "p2-tag", "key-tag1", "key-tag2"}
			session.ApplyPolicies = []string{pID, pID2}
			assert(session, expected)
		})

		t.Run("Make unique", func(t *testing.T) {
			expected := []string{"p1-tag", "p2-tag", "key-tag1", "key-tag2"}
			session.ApplyPolicies = []string{pID, pID2}
			session.Tags = append(session.Tags, "p1-tag", "key-tag1")
			assert(session, expected)
		})

		t.Run("Remove", func(t *testing.T) {
			expected := []string{"p1-tag", "p2-tag", "key-tag2"}
			session.ApplyPolicies = []string{pID, pID2}
			session.Tags = []string{"key-tag2"}
			assert(session, expected)
		})

	})
}

func TestHashKeyHandler(t *testing.T) {
	globalConf := config.Global()
	// make it to use hashes for Redis keys
	globalConf.HashKeys = true
	// enable hashed keys listing
	globalConf.EnableHashedKeysListing = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

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
		globalConf.HashKeyFunction = tc.hashFunction
		config.SetGlobal(globalConf)

		t.Run(fmt.Sprintf("%sHash fn: %s", tc.desc, tc.hashFunction), func(t *testing.T) {
			testHashKeyHandlerHelper(t, tc.expectedHashSize)
		})
		t.Run(fmt.Sprintf("%sHash fn: %s and Basic Auth", tc.desc, tc.hashFunction), func(t *testing.T) {
			testHashFuncAndBAHelper(t)
		})
	}
}

func TestHashKeyHandlerLegacyWithHashFunc(t *testing.T) {
	globalConf := config.Global()

	globalConf.HashKeys = true
	globalConf.EnableHashedKeysListing = true
	// settings to create BA session with legacy key format
	globalConf.HashKeyFunction = ""
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	// create session with legacy key format
	session := testPrepareBasicAuth(false)

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
	config.SetGlobal(globalConf)

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

func testHashKeyHandlerHelper(t *testing.T, expectedHashSize int) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI()

	withAccess := CreateStandardSession()
	withAccess.AccessRights = map[string]user.AccessDefinition{"test": {
		APIID: "test", Versions: []string{"v1"},
	}}
	withAccessJSON, _ := json.Marshal(withAccess)

	myKey := "my_key_id"
	myKeyHash := storage.HashKey(generateToken("default", myKey))

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

func testHashFuncAndBAHelper(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	session := testPrepareBasicAuth(false)

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
	globalConf := config.Global()
	// make it to use hashes for Redis keys
	globalConf.HashKeys = true
	// disable hashed keys listing
	globalConf.EnableHashedKeysListing = false
	config.SetGlobal(globalConf)

	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI()

	withAccess := CreateStandardSession()
	withAccess.AccessRights = map[string]user.AccessDefinition{"test": {
		APIID: "test", Versions: []string{"v1"},
	}}
	withAccessJSON, _ := json.Marshal(withAccess)

	myKey := "my_key_id"
	myKeyHash := storage.HashKey(generateToken("default", myKey))

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
	globalConf := config.Global()
	// make it to NOT use hashes for Redis keys
	globalConf.HashKeys = false
	config.SetGlobal(globalConf)

	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI()

	withAccess := CreateStandardSession()
	withAccess.AccessRights = map[string]user.AccessDefinition{"test": {
		APIID: "test", Versions: []string{"v1"},
	}}
	withAccessJSON, _ := json.Marshal(withAccess)

	myKeyID := "my_key_id"
	token := generateToken("default", myKeyID)
	myKeyHash := storage.HashKey(token)

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
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI()

	ts.Run(t, []test.TestCase{
		{Method: "DELETE", Path: "/tyk/cache/test", AdminAuth: true, Code: 200},
		{Method: "DELETE", Path: "/tyk/cache/test/", AdminAuth: true, Code: 200},
	}...)
}

func TestGetOAuthClients(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
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
		{Path: "/tyk/oauth/clients/test", AdminAuth: true, Code: 200, BodyMatch: `[]`},
		{Method: "POST", Path: "/tyk/oauth/clients/create", AdminAuth: true, Data: string(validOauthRequest), Code: 200},
		{Path: "/tyk/oauth/clients/test", AdminAuth: true, Code: 200, BodyMatch: `[{"client_id":"test"`},
	}...)
}

func TestCreateOAuthClient(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.UseOauth2 = true
		},
		func(spec *APISpec) {
			spec.APIID = "non_oauth_api"
			spec.UseOauth2 = false
		},
	)

	CreatePolicy(func(p *user.Policy) {
		p.ID = "p1"
		p.AccessRights = map[string]user.AccessDefinition{
			"test": {
				APIID: "test",
			},
		}
	})
	CreatePolicy(func(p *user.Policy) {
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

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.UseOauth2 = true
		},
		func(spec *APISpec) {
			spec.APIID = "non_oauth_api"
			spec.UseOauth2 = false
		},
	)

	CreatePolicy(func(p *user.Policy) {
		p.ID = "p1"
		p.AccessRights = map[string]user.AccessDefinition{
			"test": {
				APIID: "test",
			},
		}
	})
	CreatePolicy(func(p *user.Policy) {
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
			bodyMatch:    "",
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
	didSubscribe := make(chan bool)
	didReload := make(chan bool)
	cacheStore := storage.RedisCluster{}
	cacheStore.Connect()

	go func() {
		err := cacheStore.StartPubSubHandler(RedisPubSubChannel, func(v interface{}) {
			switch x := v.(type) {
			case redis.Subscription:
				didSubscribe <- true
			case redis.Message:
				notf := Notification{}
				if err := json.Unmarshal(x.Data, &notf); err != nil {
					t.Fatal(err)
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

	apisMu.Lock()
	apisByID = make(map[string]*APISpec)
	apisMu.Unlock()

	loadSampleAPI(t, apiTestDef)

	recorder := httptest.NewRecorder()

	// If we don't wait for the subscription to be done, we might do
	// the reload before pub/sub is in place to receive our message.
	<-didSubscribe
	req := withAuth(TestReq(t, "GET", uri, nil))

	mainRouter().ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Fatal("Hot reload (group) failed, response code was: ", recorder.Code)
	}

	apisMu.RLock()
	if len(apisByID) == 0 {
		t.Fatal("Hot reload (group) was triggered but no APIs were found.")
	}
	apisMu.RUnlock()

	// We wait for the right notification (NoticeGroupReload), other
	// type of notifications may be received during tests, as this
	// is the cluster channel:
	<-didReload
}

func TestHotReloadSingle(t *testing.T) {
	oldRouter := mainRouter()
	var wg sync.WaitGroup
	wg.Add(1)
	reloadURLStructure(wg.Done)
	ReloadTick <- time.Time{}
	wg.Wait()
	if mainRouter() == oldRouter {
		t.Fatal("router wasn't swapped")
	}
}

func TestHotReloadMany(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(25)
	// Spike of 25 reloads all at once, not giving any time for the
	// reload worker to pick up any of them. A single one is queued
	// and waits.
	// We get a callback for all of them, so 25 wg.Done calls.
	for i := 0; i < 25; i++ {
		reloadURLStructure(wg.Done)
	}
	// pick it up and finish it
	ReloadTick <- time.Time{}
	wg.Wait()

	// 5 reloads, but this time slower - the reload worker has time
	// to do all of them.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		reloadURLStructure(wg.Done)
		// pick it up and finish it
		ReloadTick <- time.Time{}
		wg.Wait()
	}
}

func BenchmarkApiReload(b *testing.B) {
	b.ReportAllocs()

	specs := make([]*APISpec, 100)

	for i := 0; i < 100; i++ {
		specs[i] = BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = strconv.Itoa(i + 1)
		})[0]
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loadAPIEndpoints(nil)
		loadApps(specs)
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
	r := new(http.Request)
	if ctxGetSession(r) != nil {
		t.Fatal("expected ctxGetSession to return nil")
	}
	ctxSetSession(r, &user.SessionState{}, "", false)
	if ctxGetSession(r) == nil {
		t.Fatal("expected ctxGetSession to return non-nil")
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected ctxSetSession of zero val to panic")
		}
	}()
	ctxSetSession(r, nil, "", false)
}

func TestApiLoaderLongestPathFirst(t *testing.T) {
	globalConf := config.Global()
	globalConf.EnableCustomDomains = true
	config.SetGlobal(globalConf)

	defer ResetTestConfig()

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

	ts := StartTest()
	defer ts.Close()
	LoadAPI(apis...)

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
