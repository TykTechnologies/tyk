package main

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/lonelycode/gorpc"
)

const sampleDefiniton = `{
	"name": "Tyk Test API",
	"api_id": "1",
	"org_id": "default",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {
		"auth_header_name": "authorization"
	},
	"version_data": {
		"not_versioned": false,
		"versions": {
			"v1": {
				"name": "v1",
				"expires": "2006-01-02 15:04",
				"use_extended_paths": true,
				"paths": {
					"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
					"white_list": ["v1/disallowed/blacklist/literal", "v1/disallowed/blacklist/{id}"],
					"black_list": ["v1/disallowed/whitelist/literal", "v1/disallowed/whitelist/{id}"]
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "http://example.com",
		"strip_listen_path": false
	}
}`

const nonExpiringDef = `{
	"name": "Tyk Test API",
	"api_id": "1",
	"org_id": "default",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {
		"auth_header_name": "authorization"
	},
	"version_data": {
		"not_versioned": false,
		"versions": {
			"v1": {
				"name": "v1",
				"expires": "3000-01-02 15:04",
				"paths": {
					"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
					"white_list": ["v1/allowed/whitelist/literal", "v1/allowed/whitelist/{id}"],
					"black_list": ["v1/disallowed/blacklist/literal", "v1/disallowed/blacklist/{id}"]
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "http://example.com",
		"strip_listen_path": false
	}
}`

const nonExpiringMultiDef = `{
	"name": "Tyk Test API",
	"api_id": "1",
	"org_id": "default",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {
		"auth_header_name": "authorization"
	},
	"version_data": {
		"not_versioned": false,
		"versions": {
			"v1": {
				"name": "v1",
				"expires": "3000-01-02 15:04",
				"paths": {
					"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
					"white_list": ["v1/allowed/whitelist/literal", "v1/allowed/whitelist/{id}"],
					"black_list": ["v1/disallowed/blacklist/literal", "v1/disallowed/blacklist/{id}"]
				}
			},
			"v2": {
				"name": "v2",
				"expires": "3000-01-02 15:04",
				"paths": {
					"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
					"white_list": [],
					"black_list": ["v1/disallowed/blacklist/literal"]
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "http://example.com",
		"strip_listen_path": false
	}
}`

func createDefinitionFromString(defStr string) *APISpec {
	var loader = APIDefinitionLoader{}
	def, rawDef := loader.ParseDefinition([]byte(defStr))
	def.RawData = rawDef
	spec := loader.MakeSpec(def)
	spec.APIDefinition = def
	return spec
}

func TestExpiredRequest(t *testing.T) {
	uri := "/v1/bananaphone"
	method := "GET"

	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("version", "v1")
	if err != nil {
		t.Fatal(err)
	}

	spec := createDefinitionFromString(sampleDefiniton)

	ok, status, _ := spec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as expiry date is in the past!")
	}

	if status != VersionExpired {
		t.Error("Request should return expired status!")
		t.Error(status)
	}
}

func TestNotVersioned(t *testing.T) {
	uri := "v1/allowed/whitelist/literal"
	method := "GET"

	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)

	if err != nil {
		t.Fatal(err)
	}

	spec := createDefinitionFromString(nonExpiringDef)
	spec.VersionData.NotVersioned = true

	//	writeDefToFile(spec.APIDefinition)

	ok, status, _ := spec.IsRequestValid(req)
	if !ok {
		t.Error("Request should pass as versioning not in play!")
	}

	if status != StatusOk {
		t.Error("Request should return StatusOk status!")
		t.Error(status)
	}
}

func TestMissingVersion(t *testing.T) {
	uri := "/v1/bananaphone"
	method := "GET"

	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}

	spec := createDefinitionFromString(sampleDefiniton)

	ok, status, _ := spec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as there is no version number!")
	}

	if status != VersionNotFound {
		t.Error("Request should return version not found status!")
		t.Error(status)
	}
}

func TestWrongVersion(t *testing.T) {
	uri := "/v1/bananaphone"
	method := "GET"

	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v2")

	spec := createDefinitionFromString(sampleDefiniton)

	ok, status, _ := spec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as version number is wrong!")
	}

	if status != VersionDoesNotExist {
		t.Error("Request should return version doesn't exist status!")
		t.Error(status)
	}
}

func TestBlacklistLinks(t *testing.T) {
	uri := "v1/disallowed/blacklist/literal"
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	spec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := spec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as URL is blacklisted!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return endpoint disallowed status!")
		t.Error(status)
	}

	uri = "v1/disallowed/blacklist/abacab12345"
	method = "GET"
	param = make(url.Values)
	req, err = http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	ok, status, _ = spec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as URL (with dynamic ID) is blacklisted!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return endpoint disallowed status for regex blacklists too!")
		t.Error(status)
	}
}

func TestWhiteLIstLinks(t *testing.T) {
	uri := "v1/allowed/whitelist/literal"
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	spec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := spec.IsRequestValid(req)
	if !ok {
		t.Error("Request should be OK as URL is whitelisted!")
	}

	if status != StatusOk {
		t.Error("Request should return StatusOk!")
		t.Error(status)
	}

	uri = "v1/allowed/whitelist/12345abans"
	method = "GET"
	param = make(url.Values)
	req, err = http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	ok, status, _ = spec.IsRequestValid(req)
	if !ok {
		t.Error("Request should be OK as URL is whitelisted (regex)!")
	}

	if status != StatusOk {
		t.Error("Regex whitelist Request should return StatusOk!")
		t.Error(status)
	}
}

func TestWhiteListBlock(t *testing.T) {
	uri := "v1/allowed/bananaphone"
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	spec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := spec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as things not in whitelist should be rejected!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return EndPointNotAllowed!")
		t.Error(status)
	}
}

func TestIgnored(t *testing.T) {
	uri := "/v1/ignored/noregex"
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v1")

	spec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := spec.IsRequestValid(req)
	if !ok {
		t.Error("Request should pass, URL is ignored")
	}

	if status != StatusOkAndIgnore {
		t.Error("Request should return StatusOkAndIgnore!")
		t.Error(status)
	}
}

func TestBlacklistLinksMulti(t *testing.T) {
	uri := "v1/disallowed/blacklist/literal"
	method := "GET"
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v2")

	spec := createDefinitionFromString(nonExpiringMultiDef)

	ok, status, _ := spec.IsRequestValid(req)
	if ok {
		t.Error("Request should fail as URL is blacklisted!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return endpoint disallowed status!")
		t.Error(status)
	}

	uri = "v1/disallowed/blacklist/abacab12345"
	method = "GET"
	param = make(url.Values)
	req, err = http.NewRequest(method, uri+param.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("version", "v2")

	ok, status, _ = spec.IsRequestValid(req)
	if !ok {
		t.Error("Request should be OK as in v2 this URL is not blacklisted")
		t.Error(spec.RxPaths["v2"])
	}

	if status != StatusOk {
		t.Error("Request should return StatusOK as URL not blacklisted!")
		t.Error(status)
	}
}

func startRPCMock(dispatcher *gorpc.Dispatcher) *gorpc.Server {
	config.SlaveOptions.UseRPC = true
	config.SlaveOptions.RPCKey = "test_org"
	config.SlaveOptions.APIKey = "test"

	server := gorpc.NewTCPServer(":9090", dispatcher.NewHandlerFunc())
	go server.Serve()
	config.SlaveOptions.ConnectionString = server.Addr

	RPCCLientSingleton = gorpc.NewTCPClient(server.Addr)
	RPCCLientSingleton.Conns = 1
	RPCCLientSingleton.Start()
	RPCClientIsConnected = true
	RPCFuncClientSingleton = GetDispatcher().NewFuncClient(RPCCLientSingleton)

	return server
}

func stopRPCMock(server *gorpc.Server) {
	config.SlaveOptions.ConnectionString = ""
	config.SlaveOptions.RPCKey = ""
	config.SlaveOptions.APIKey = ""
	config.SlaveOptions.UseRPC = false

	server.Listener.Close()
	server.Stop()

	RPCCLientSingleton.Stop()
	RPCClientIsConnected = false
	RPCClients = map[string]chan int{}
	RPCCLientSingleton = nil
	RPCFuncClientSingleton = nil
}

func TestGetAPISpecsRPCFailure(t *testing.T) {
	// Mock RPC
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *DefRequest) (string, error) {
		return "malformed json", nil
	})
	dispatcher.AddFunc("Login", func(clientAddr string, userKey string) bool {
		return true
	})

	rpc := startRPCMock(dispatcher)
	defer stopRPCMock(rpc)

	specs := getAPISpecs()
	if len(specs) != 0 {
		t.Error("Should return empty value for malformed rpc response", specs)
	}
}

func TestGetAPISpecsRPCSuccess(t *testing.T) {
	// Mock RPC
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *DefRequest) (string, error) {
		return "[{}]", nil
	})
	dispatcher.AddFunc("Login", func(clientAddr string, userKey string) bool {
		return true
	})

	rpc := startRPCMock(dispatcher)
	defer stopRPCMock(rpc)

	specs := getAPISpecs()
	if len(specs) != 1 {
		t.Error("Should return array with one spec", specs)
	}

}
