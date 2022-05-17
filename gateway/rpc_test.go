//go:build !race
// +build !race

package gateway

import (
	"net/http"
	_ "net/http"
	"testing"
	"time"

	"github.com/TykTechnologies/gorpc"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/test"
)

func StartSlaveGw(connectionString string, groupId string) *Test {
	conf := func(globalConf *config.Config) {
		globalConf.SlaveOptions.UseRPC = true
		globalConf.SlaveOptions.RPCKey = "test_org"
		globalConf.SlaveOptions.APIKey = "test"
		globalConf.Policies.PolicySource = "rpc"
		globalConf.SlaveOptions.GroupID = groupId
		globalConf.SlaveOptions.CallTimeout = 1
		globalConf.SlaveOptions.RPCPoolSize = 2
		globalConf.AuthOverride.ForceAuthProvider = true
		globalConf.AuthOverride.AuthProvider.StorageEngine = "rpc"
		globalConf.SlaveOptions.ConnectionString = connectionString
	}
	return StartTest(conf)
}

func startRPCMock(dispatcher *gorpc.Dispatcher) (*gorpc.Server, string) {

	rpc.GlobalRPCCallTimeout = 100 * time.Millisecond

	server := gorpc.NewTCPServer("127.0.0.1:0", dispatcher.NewHandlerFunc())
	list := &customListener{}
	server.Listener = list
	server.LogError = gorpc.NilErrorLogger

	if err := server.Start(); err != nil {
		panic(err)
	}

	return server, list.L.Addr().String()
}

func stopRPCMock(server *gorpc.Server) {

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
		// the firts time called is when we start the slave gateway
		return a()
	})
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		return true
	})
	dispatcher.AddFunc("GetPolicies", func(orgId string) (string, error) {
		return `[]`, nil
	})

	rpcMock, connectionString := startRPCMock(dispatcher)
	defer stopRPCMock(rpcMock)

	ts := StartSlaveGw(connectionString, "")
	defer ts.Close()

	store := RPCStorageHandler{Gw: ts.Gw}
	store.Connect()

	// Three cases: 1 API, 2 APIs and Malformed data
	exp := []int{1, 2, 2}
	for _, e := range exp {
		ts.Gw.DoReload()
		n := ts.Gw.apisByIDLen()
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
		rpcMock, connectionString := startRPCMock(dispatcher)
		defer stopRPCMock(rpcMock)

		ts := StartSlaveGw(connectionString, "")
		defer ts.Close()

		GetKeyCounter = 0
		apiBackup, _ := ts.Gw.LoadDefinitionsFromRPCBackup()
		if len(apiBackup) != 1 {
			t.Fatal("Should have APIs in backup")
		}

		policyBackup, _ := ts.Gw.LoadPoliciesFromRPCBackup()
		if len(policyBackup) != 1 {
			t.Fatal("Should have Policies in backup")
		}

		authHeaders := map[string]string{"Authorization": "test"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: authHeaders, Code: 200},
		}...)

		count, _ := ts.Gw.syncAPISpecs()
		if count != 1 {
			t.Error("Should return array with one spec", ts.Gw.apiSpecs)
		}

		if GetKeyCounter != 2 {
			t.Errorf("getKey should have been called 2 times, instead, was called %v times", GetKeyCounter)
		}
	})

	t.Run("RPC down, cold start, load backup", func(t *testing.T) {

		// Point rpc to non existent address
		conf := func(globalConf *config.Config) {
			globalConf.SlaveOptions.ConnectionString = testHttpFailure
			globalConf.SlaveOptions.UseRPC = true
			globalConf.SlaveOptions.RPCKey = "test_org"
			globalConf.SlaveOptions.APIKey = "test"
			globalConf.Policies.PolicySource = "rpc"
		}

		GetKeyCounter = 0
		// RPC layer is down,
		ts := StartTest(conf, TestConfig{})
		defer ts.Close()

		// Wait for backup to load
		time.Sleep(100 * time.Millisecond)
		ts.Gw.DoReload()

		rpc.SetEmergencyMode(t, true)
		cachedAuth := map[string]string{"Authorization": "test"}
		notCachedAuth := map[string]string{"Authorization": "nope1"}
		// Still works, since it knows about cached key
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
		rpcMock, connectionString := startRPCMock(dispatcher)
		defer stopRPCMock(rpcMock)

		ts := StartSlaveGw(connectionString, "")
		defer ts.Close()

		time.Sleep(1000 * time.Millisecond)

		cachedAuth := map[string]string{"Authorization": "test"}
		notCachedAuth := map[string]string{"Authorization": "nope2"}

		if count, _ := ts.Gw.syncAPISpecs(); count != 2 {
			t.Error("Should fetch latest specs", count)
		}

		if count, _ := ts.Gw.syncPolicies(); count != 2 {
			t.Error("Should fetch latest policies", count)
		}

		// ToDo: if listen path collides, then gw will modify them, hence we need to fetch it
		ts.Run(t, []test.TestCase{
			{Path: "/sample-test", Headers: cachedAuth, Code: 200},
			{Path: "/sample-test", Headers: notCachedAuth, Code: 200},
		}...)
	})

	t.Run("RPC is back, live reload", func(t *testing.T) {
		rpcMock, connectionString := startRPCMock(dispatcher)

		ts := StartSlaveGw(connectionString, "")
		defer ts.Close()
		time.Sleep(100 * time.Millisecond)

		authHeaders := map[string]string{"Authorization": "test"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: authHeaders, Code: 200},
		}...)

		rpcMock.Listener.Close()
		rpcMock.Stop()

		cached := map[string]string{"Authorization": "test"}
		notCached := map[string]string{"Authorization": "nope3"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: cached, Code: 200},
			{Path: "/sample", Headers: notCached, Code: 403},
		}...)

		// Dynamically restart RPC layer
		rpcMock = gorpc.NewTCPServer(rpcMock.Listener.(*customListener).L.Addr().String(), dispatcher.NewHandlerFunc())
		list := &customListener{}
		rpcMock.Listener = list
		rpcMock.LogError = gorpc.NilErrorLogger
		if err := rpcMock.Start(); err != nil {
			panic(err)
		}

		// Internal gorpc reconnect timeout is 1 second
		time.Sleep(1 * time.Second)

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

	rpcMock, connectionString := startRPCMock(dispatcher)
	defer stopRPCMock(rpcMock)

	ts := StartSlaveGw(connectionString, "")
	defer ts.Close()

	t.Run("Should load apis when redis is down", func(t *testing.T) {

		ts.Gw.RedisController.DisableRedis(true)
		//defer ts.Gw.RedisController.DisableRedis((false)

		authHeaders := map[string]string{"Authorization": "test"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: authHeaders, Code: http.StatusOK},
		}...)
	})

	t.Run("Should reload when redis is back up", func(t *testing.T) {

		ts.Gw.RedisController.DisableRedis(true)
		event := make(chan struct{}, 1)
		ts.Gw.OnConnect = func() {
			event <- struct{}{}
			ts.Gw.DoReload()
		}

		select {
		case <-event:
			t.Fatal("OnConnect should only run after reconnection")
		case <-time.After(1 * time.Second):
		}
		ts.Gw.RedisController.DisableRedis(false)

		select {
		case <-event:
		case <-time.After(3 * time.Second):
			t.Fatal("Expected redis to reconnect and call the callback")
		}
		time.Sleep(time.Second)
		authHeaders := map[string]string{"Authorization": "test"}
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: authHeaders, Code: http.StatusOK},
		}...)
	})

}

func TestOrgSessionWithRPCDown(t *testing.T) {
	//we need rpc down
	conf := func(globalConf *config.Config) {
		globalConf.SlaveOptions.ConnectionString = testHttpFailure
		globalConf.SlaveOptions.UseRPC = true
		globalConf.SlaveOptions.RPCKey = "test_org"
		globalConf.SlaveOptions.APIKey = "test"
		globalConf.Policies.PolicySource = "rpc"
	}
	ts := StartTest(conf)
	defer ts.Close()

	m := BaseMiddleware{
		Spec: &APISpec{
			GlobalConfig: config.Config{
				EnforceOrgDataAge: true,
			},
			OrgSessionManager: mockStore{},
		},
		logger: mainLog,
		Gw:     ts.Gw,
	}
	// reload so we force to fall in emergency mode
	ts.Gw.DoReload()

	_, found := m.OrgSession(sess.OrgID)
	if found {
		t.Fatal("org  session should be null:")
	}
}
