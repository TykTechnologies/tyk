// +build !race

package gateway

import (
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/cli"

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

	// Test RPC
	callCount := 0
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *apidef.DefRequest) (string, error) {
		if callCount == 0 {
			callCount += 1
			return `[]`, nil
		}

		if callCount == 1 {
			callCount += 1
			return apiDefListTest, nil
		}

		if callCount == 2 {
			callCount += 1
			return apiDefListTest2, nil
		}

		if callCount == 3 {
			callCount += 1
			return "malformed json", nil
		}

		// clean up
		return `[]`, nil
	})
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		return true
	})
	dispatcher.AddFunc("GetPolicies", func(orgId string) (string, error) {
		return `[]`, nil
	})

	rpc := startRPCMock(dispatcher)
	defer stopRPCMock(rpc)

	// Three cases: 1 API, 2 APIs and Malformed data
	exp := []int{1, 4, 6, 6, 2}
	if *cli.HTTPProfile {
		exp = []int{4, 6, 8, 8, 4}
	}
	for _, e := range exp {
		DoReload()

		rtCnt := 0
		mainRouter().Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			rtCnt += 1
			//fmt.Println(route.GetPathTemplate())
			return nil
		})

		if rtCnt != e {
			t.Errorf("There should be %v routes, got %v", e, rtCnt)
		}
	}
}

// Our RPC layer too racy, but not harmul, mostly global variables like RPCIsClientConnected
func TestSyncAPISpecsRPCFailure(t *testing.T) {
	// Test RPC
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *apidef.DefRequest) (string, error) {
		return "malformed json", nil
	})
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		return true
	})

	rpc := startRPCMock(dispatcher)
	defer stopRPCMock(rpc)

	count, _ := syncAPISpecs()
	if count != 0 {
		t.Error("Should return empty value for malformed rpc response", apiSpecs)
	}
}

func TestSyncAPISpecsRPCSuccess(t *testing.T) {
	// Test RPC
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

	t.Run("RPC is live", func(t *testing.T) {
		rpc := startRPCMock(dispatcher)
		defer stopRPCMock(rpc)
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
	})

	t.Run("RPC down, cold start, load backup", func(t *testing.T) {
		// Point rpc to non existent address
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
		select {
		case ReloadTick <- time.Time{}:
		case <-time.After(100 * time.Millisecond):
		}
		time.Sleep(100 * time.Millisecond)

		cachedAuth := map[string]string{"Authorization": "test"}
		notCachedAuth := map[string]string{"Authorization": "nope1"}
		// Stil works, since it knows about cached key
		ts.Run(t, []test.TestCase{
			{Path: "/sample", Headers: cachedAuth, Code: 200},
			{Path: "/sample", Headers: notCachedAuth, Code: 403},
		}...)

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
