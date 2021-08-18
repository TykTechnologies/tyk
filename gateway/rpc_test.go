// +build !race

package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/storage"

	"github.com/TykTechnologies/gorpc"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/test"
)

func startRPCMock(dispatcher *gorpc.Dispatcher) *gorpc.Server {

	rpc.GlobalRPCCallTimeout = 100 * time.Millisecond

	globalConf := config.Global()
	globalConf.SlaveOptions.UseRPC = true
	globalConf.SlaveOptions.RPCKey = "test_org"
	globalConf.SlaveOptions.APIKey = "test"
	globalConf.Policies.PolicySource = "rpc"
	globalConf.SlaveOptions.CallTimeout = 1
	globalConf.SlaveOptions.RPCPoolSize = 2
	globalConf.AuthOverride.ForceAuthProvider = true
	globalConf.AuthOverride.AuthProvider.StorageEngine = "rpc"

	server := gorpc.NewTCPServer("127.0.0.1:0", dispatcher.NewHandlerFunc())
	list := &customListener{}
	server.Listener = list
	server.LogError = gorpc.NilErrorLogger

	if err := server.Start(); err != nil {
		panic(err)
	}
	globalConf.SlaveOptions.ConnectionString = list.L.Addr().String()

	config.SetGlobal(globalConf)

	return server
}

func stopRPCMock(server *gorpc.Server) {
	globalConf := config.Global()
	globalConf.SlaveOptions.ConnectionString = ""
	globalConf.SlaveOptions.RPCKey = ""
	globalConf.SlaveOptions.APIKey = ""
	globalConf.SlaveOptions.UseRPC = false
	globalConf.Policies.PolicySource = ""
	globalConf.AuthOverride.ForceAuthProvider = false
	config.SetGlobal(globalConf)

	if server != nil {
		server.Listener.Close()
		server.Stop()
	}

	rpc.Reset()
}

const apiDefListTest = `[{
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
}]`

const apiDefListTest2 = `[{
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
},
{
	"api_id": "2",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"versions": {
			"v2": {"name": "v2"}
		}
	},
	"proxy": {
		"listen_path": "/v2",
		"target_url": "` + TestHttpAny + `"
	}
}]`

func TestSyncAPISpecsRPCFailure_CheckGlobals(t *testing.T) {
	ts := StartTest()
	defer ts.Close()
	defer ResetTestConfig()
	// We test to check if we are actually calling the GetApiDefinitions and
	// GetPolicies.
	a := func() func() (string, error) {
		x := 0
		return func() (string, error) {
			defer func() {
				x++
			}()
			switch x {
			case 1:
				return apiDefListTest, nil
			case 2:
				return apiDefListTest2, nil
			case 3:
				return "malformed json", nil
			default:
				return `[]`, nil
			}
		}
	}()
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *apidef.DefRequest) (string, error) {
		return a()
	})
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		return true
	})
	dispatcher.AddFunc("GetPolicies", func(orgId string) (string, error) {
		return `[]`, nil
	})

	rpcMock := startRPCMock(dispatcher)
	defer stopRPCMock(rpcMock)

	store := RPCStorageHandler{}
	store.Connect()
	rpc.ForceConnected(t)

	// Three cases: 1 API, 2 APIs and Malformed data
	exp := []int{0, 1, 2, 2}
	for _, e := range exp {
		DoReload()
		n := apisByIDLen()
		if n != e {
			t.Errorf("There should be %v api's, got %v", e, n)
		}
	}
}

func TestSyncAPISpecsRPCSuccess(t *testing.T) {
	// Test RPC
	rpc.UseSyncLoginRPC = true
	var GetKeyCounter int
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *apidef.DefRequest) (string, error) {
		return jsonMarshalString(BuildAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
		})), nil
	})
	dispatcher.AddFunc("GetPolicies", func(clientAddr string, orgid string) (string, error) {
		return `[{"_id":"507f191e810c19729de860ea", "rate":1, "per":1}]`, nil
	})
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		return true
	})
	dispatcher.AddFunc("GetKey", func(clientAddr, key string) (string, error) {
		GetKeyCounter++
		return jsonMarshalString(CreateStandardSession()), nil
	})

	t.Run("RPC is live", func(t *testing.T) {
		GetKeyCounter = 0
		rpcMock := startRPCMock(dispatcher)
		defer stopRPCMock(rpcMock)
		ts := StartTest()
		defer ts.Close()

		apiBackup, _ := LoadDefinitionsFromRPCBackup()
		if len(apiBackup) != 1 {
			t.Fatal("Should have APIs in backup")
		}

		policyBackup, _ := LoadPoliciesFromRPCBackup()
		if len(policyBackup) != 1 {
			t.Fatal("Should have Policies in backup")
		}

		authHeaders := map[string]string{"Authorization": "test"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: authHeaders, Code: 200},
		}...)

		count, _ := syncAPISpecs()
		if count != 1 {
			t.Error("Should return array with one spec", apiSpecs)
		}

		if GetKeyCounter != 2 {
			t.Error("getKey should have been called 2 times")
		}
	})

	t.Run("RPC down, cold start, load backup", func(t *testing.T) {
		// Point rpc to non existent address
		GetKeyCounter = 0
		globalConf := config.Global()
		globalConf.SlaveOptions.ConnectionString = testHttpFailure
		globalConf.SlaveOptions.UseRPC = true
		globalConf.SlaveOptions.RPCKey = "test_org"
		globalConf.SlaveOptions.APIKey = "test"
		globalConf.Policies.PolicySource = "rpc"
		config.SetGlobal(globalConf)

		// RPC layer is down
		ts := StartTest()
		defer ts.Close()

		// Wait for backup to load
		time.Sleep(100 * time.Millisecond)
		DoReload()

		rpc.SetEmergencyMode(t, true)
		cachedAuth := map[string]string{"Authorization": "test"}
		notCachedAuth := map[string]string{"Authorization": "nope1"}
		// Stil works, since it knows about cached key
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: cachedAuth, Code: 200},
			{Path: "/sample", Headers: notCachedAuth, Code: 403},
		}...)

		// when rpc in emergency mode, then we must not
		// request keys in rpc
		if GetKeyCounter != 0 {
			t.Error("getKey should have been called 0 times")
		}
		stopRPCMock(nil)
	})

	t.Run("RPC is back, hard reload", func(t *testing.T) {
		rpc.ResetEmergencyMode()

		dispatcher := gorpc.NewDispatcher()
		dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *apidef.DefRequest) (string, error) {
			return jsonMarshalString(BuildAPI(
				func(spec *APISpec) { spec.UseKeylessAccess = false },
				func(spec *APISpec) { spec.UseKeylessAccess = false },
			)), nil
		})
		dispatcher.AddFunc("GetPolicies", func(clientAddr string, orgid string) (string, error) {
			return `[{"_id":"507f191e810c19729de860ea", "rate":1, "per":1}, {"_id":"507f191e810c19729de860eb", "rate":1, "per":1}]`, nil
		})
		dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
			return true
		})
		dispatcher.AddFunc("GetKey", func(clientAddr, key string) (string, error) {
			return jsonMarshalString(CreateStandardSession()), nil
		})
		// Back to live
		rpc := startRPCMock(dispatcher)
		defer stopRPCMock(rpc)
		ts := StartTest()
		defer ts.Close()

		time.Sleep(100 * time.Millisecond)

		cachedAuth := map[string]string{"Authorization": "test"}
		notCachedAuth := map[string]string{"Authorization": "nope2"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: cachedAuth, Code: 200},
			{Path: "/sample", Headers: notCachedAuth, Code: 200},
		}...)

		if count, _ := syncAPISpecs(); count != 2 {
			t.Error("Should fetch latest specs", count)
		}

		if count, _ := syncPolicies(); count != 2 {
			t.Error("Should fetch latest policies", count)
		}
	})

	t.Run("RPC is back, live reload", func(t *testing.T) {
		rpc := startRPCMock(dispatcher)
		ts := StartTest()
		defer ts.Close()

		time.Sleep(100 * time.Millisecond)

		authHeaders := map[string]string{"Authorization": "test"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: authHeaders, Code: 200},
		}...)

		rpc.Listener.Close()
		rpc.Stop()

		cached := map[string]string{"Authorization": "test"}
		notCached := map[string]string{"Authorization": "nope3"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: cached, Code: 200},
			{Path: "/sample", Headers: notCached, Code: 403},
		}...)

		// Dynamically restart RPC layer
		rpc = gorpc.NewTCPServer(rpc.Listener.(*customListener).L.Addr().String(), dispatcher.NewHandlerFunc())
		list := &customListener{}
		rpc.Listener = list
		rpc.LogError = gorpc.NilErrorLogger
		if err := rpc.Start(); err != nil {
			panic(err)
		}
		defer stopRPCMock(rpc)

		// Internal gorpc reconnect timeout is 1 second
		time.Sleep(1000 * time.Millisecond)

		notCached = map[string]string{"Authorization": "nope4"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: notCached, Code: 200},
		}...)
	})
}

func TestSyncAPISpecsRPC_redis_failure(t *testing.T) {
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *apidef.DefRequest) (string, error) {
		return jsonMarshalString(BuildAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
		})), nil
	})
	dispatcher.AddFunc("GetPolicies", func(clientAddr string, orgid string) (string, error) {
		return `[{"_id":"507f191e810c19729de860ea", "rate":1, "per":1}]`, nil
	})
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		return true
	})
	dispatcher.AddFunc("GetKey", func(clientAddr, key string) (string, error) {
		return jsonMarshalString(CreateStandardSession()), nil
	})
	rpc := startRPCMock(dispatcher)
	defer stopRPCMock(rpc)

	t.Run("Should load apis when redis is down", func(t *testing.T) {
		storage.DisableRedis(true)
		defer storage.DisableRedis(false)
		ts := StartTest()
		defer ts.Close()

		authHeaders := map[string]string{"Authorization": "test"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: authHeaders, Code: http.StatusOK},
		}...)
	})

	t.Run("Should reload when redis is back up", func(t *testing.T) {
		storage.DisableRedis(true)
		ts := StartTest()
		defer ts.Close()
		event := make(chan struct{}, 1)
		OnConnect = func() {
			event <- struct{}{}
			DoReload()
		}
		defer func() {
			OnConnect = nil
		}()

		select {
		case <-event:
			t.Fatal("OnConnect should only run after reconnection")
		case <-time.After(1 * time.Second):
		}
		storage.DisableRedis(false)

		select {
		case <-event:
		case <-time.After(3 * time.Second):
			t.Fatal("Expected redis to reconnect and call the callback")
		}
		time.Sleep(time.Second)
		authHeaders := map[string]string{"Authorization": "test"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: authHeaders, Code: 200},
		}...)
	})

}

func TestOrgSessionWithRPCDown(t *testing.T) {
	//we need rpc down
	globalConf := config.Global()
	globalConf.SlaveOptions.ConnectionString = testHttpFailure
	globalConf.SlaveOptions.UseRPC = true
	globalConf.SlaveOptions.RPCKey = "test_org"
	globalConf.SlaveOptions.APIKey = "test"
	globalConf.Policies.PolicySource = "rpc"
	config.SetGlobal(globalConf)

	defer func() {
		globalConf.SlaveOptions.ConnectionString = ""
		globalConf.SlaveOptions.UseRPC = false
		globalConf.SlaveOptions.RPCKey = ""
		globalConf.SlaveOptions.APIKey = ""
		globalConf.Policies.PolicySource = ""
		config.SetGlobal(globalConf)
	}()

	ts := StartTest()
	defer ts.Close()

	m := BaseMiddleware{
		Spec: &APISpec{
			GlobalConfig: config.Config{
				EnforceOrgDataAge: true,
			},
			OrgSessionManager: mockStore{},
		},
		logger: mainLog,
	}
	// reload so we force to fall in emergency mode
	DoReload()

	_, found := m.OrgSession(sess.OrgID)
	if found {
		t.Fatal("org  session should be null:")
	}
}
