package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/lonelycode/gorpc"

	"github.com/TykTechnologies/tyk/config"
)

const sampleDefiniton = `{
	"api_id": "1",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"versions": {
			"v1": {
				"name": "v1",
				"expires": "2006-01-02 15:04",
				"paths": {
					"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
					"white_list": ["/v1/disallowed/blacklist/literal", "/v1/disallowed/blacklist/{id}"],
					"black_list": ["/v1/disallowed/whitelist/literal", "/v1/disallowed/whitelist/{id}"]
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	}
}`

const nonExpiringDef = `{
	"api_id": "1",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"versions": {
			"v1": {
				"name": "v1",
				"expires": "3000-01-02 15:04",
				"paths": {
					"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
					"white_list": ["/v1/allowed/whitelist/literal", "/v1/allowed/whitelist/{id}"],
					"black_list": ["/v1/disallowed/blacklist/literal", "/v1/disallowed/blacklist/{id}"]
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	}
}`

const nonExpiringMultiDef = `{
	"api_id": "1",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"versions": {
			"v1": {
				"name": "v1",
				"expires": "3000-01-02 15:04",
				"paths": {
					"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
					"white_list": ["/v1/allowed/whitelist/literal", "/v1/allowed/whitelist/{id}"],
					"black_list": ["/v1/disallowed/blacklist/literal", "/v1/disallowed/blacklist/{id}"]
				}
			},
			"v2": {
				"name": "v2",
				"expires": "3000-01-02 15:04",
				"paths": {
					"ignored": ["/v1/ignored/noregex", "/v1/ignored/with_id/{id}"],
					"black_list": ["/v1/disallowed/blacklist/literal"]
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	}
}`

func createDefinitionFromString(defStr string) *APISpec {
	loader := APIDefinitionLoader{}
	def := loader.ParseDefinition(strings.NewReader(defStr))
	spec := loader.MakeSpec(def)
	return spec
}

func TestExpiredRequest(t *testing.T) {
	req := testReq(t, "GET", "/v1/bananaphone", nil)
	req.Header.Set("version", "v1")

	spec := createDefinitionFromString(sampleDefiniton)

	ok, status, _ := spec.RequestValid(req)
	if ok {
		t.Error("Request should fail as expiry date is in the past!")
	}

	if status != VersionExpired {
		t.Error("Request should return expired status!")
		t.Error(status)
	}
}

func TestNotVersioned(t *testing.T) {
	req := testReq(t, "GET", "/v1/allowed/whitelist/literal", nil)

	spec := createDefinitionFromString(nonExpiringDef)
	spec.VersionData.NotVersioned = true

	//	writeDefToFile(spec.APIDefinition)

	ok, status, _ := spec.RequestValid(req)
	if !ok {
		t.Error("Request should pass as versioning not in play!")
	}

	if status != StatusOk {
		t.Error("Request should return StatusOk status!")
		t.Error(status)
	}
}

func TestMissingVersion(t *testing.T) {
	req := testReq(t, "GET", "/v1/bananaphone", nil)

	spec := createDefinitionFromString(sampleDefiniton)

	ok, status, _ := spec.RequestValid(req)
	if ok {
		t.Error("Request should fail as there is no version number!")
	}

	if status != VersionNotFound {
		t.Error("Request should return version not found status!")
		t.Error(status)
	}
}

func TestWrongVersion(t *testing.T) {
	req := testReq(t, "GET", "/v1/bananaphone", nil)
	req.Header.Set("version", "v2")

	spec := createDefinitionFromString(sampleDefiniton)

	ok, status, _ := spec.RequestValid(req)
	if ok {
		t.Error("Request should fail as version number is wrong!")
	}

	if status != VersionDoesNotExist {
		t.Error("Request should return version doesn't exist status!")
		t.Error(status)
	}
}

func TestBlacklistLinks(t *testing.T) {
	req := testReq(t, "GET", "/v1/disallowed/blacklist/literal", nil)
	req.Header.Set("version", "v1")

	spec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := spec.RequestValid(req)
	if ok {
		t.Error("Request should fail as URL is blacklisted!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return endpoint disallowed status!")
		t.Error(status)
	}

	req = testReq(t, "GET", "/v1/disallowed/blacklist/abacab12345", nil)
	req.Header.Set("version", "v1")

	ok, status, _ = spec.RequestValid(req)
	if ok {
		t.Error("Request should fail as URL (with dynamic ID) is blacklisted!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return endpoint disallowed status for regex blacklists too!")
		t.Error(status)
	}
}

func TestWhiteLIstLinks(t *testing.T) {
	req := testReq(t, "GET", "/v1/allowed/whitelist/literal", nil)
	req.Header.Set("version", "v1")

	spec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := spec.RequestValid(req)
	if !ok {
		t.Error("Request should be OK as URL is whitelisted!")
	}

	if status != StatusOk {
		t.Error("Request should return StatusOk!")
		t.Error(status)
	}

	req = testReq(t, "GET", "/v1/allowed/whitelist/12345abans", nil)
	req.Header.Set("version", "v1")

	ok, status, _ = spec.RequestValid(req)
	if !ok {
		t.Error("Request should be OK as URL is whitelisted (regex)!")
	}

	if status != StatusOk {
		t.Error("Regex whitelist Request should return StatusOk!")
		t.Error(status)
	}
}

func TestWhiteListBlock(t *testing.T) {
	req := testReq(t, "GET", "/v1/allowed/bananaphone", nil)
	req.Header.Set("version", "v1")

	spec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := spec.RequestValid(req)
	if ok {
		t.Error("Request should fail as things not in whitelist should be rejected!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return EndPointNotAllowed!")
		t.Error(status)
	}
}

func TestIgnored(t *testing.T) {
	req := testReq(t, "GET", "/v1/ignored/noregex", nil)
	req.Header.Set("version", "v1")

	spec := createDefinitionFromString(nonExpiringDef)

	ok, status, _ := spec.RequestValid(req)
	if !ok {
		t.Error("Request should pass, URL is ignored")
	}

	if status != StatusOkAndIgnore {
		t.Error("Request should return StatusOkAndIgnore!")
		t.Error(status)
	}
}

func TestBlacklistLinksMulti(t *testing.T) {
	req := testReq(t, "GET", "/v1/disallowed/blacklist/literal", nil)
	req.Header.Set("version", "v2")

	spec := createDefinitionFromString(nonExpiringMultiDef)

	ok, status, _ := spec.RequestValid(req)
	if ok {
		t.Error("Request should fail as URL is blacklisted!")
	}

	if status != EndPointNotAllowed {
		t.Error("Request should return endpoint disallowed status!")
		t.Error(status)
	}

	req = testReq(t, "GET", "/v1/disallowed/blacklist/abacab12345", nil)
	req.Header.Set("version", "v2")

	ok, status, _ = spec.RequestValid(req)
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
	config.Global.SlaveOptions.UseRPC = true
	config.Global.SlaveOptions.RPCKey = "test_org"
	config.Global.SlaveOptions.APIKey = "test"

	server := gorpc.NewTCPServer("127.0.0.1:0", dispatcher.NewHandlerFunc())
	list := &customListener{}
	server.Listener = list
	server.LogError = gorpc.NilErrorLogger

	if err := server.Start(); err != nil {
		panic(err)
	}
	config.Global.SlaveOptions.ConnectionString = list.L.Addr().String()

	return server
}

func stopRPCMock(server *gorpc.Server) {
	config.Global.SlaveOptions.ConnectionString = ""
	config.Global.SlaveOptions.RPCKey = ""
	config.Global.SlaveOptions.APIKey = ""
	config.Global.SlaveOptions.UseRPC = false

	server.Listener.Close()
	server.Stop()

	RPCCLientSingleton.Stop()
	RPCClientIsConnected = false
	RPCCLientSingleton = nil
	RPCFuncClientSingleton = nil
}

func TestSyncAPISpecsRPCFailure(t *testing.T) {
	// Mock RPC
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *DefRequest) (string, error) {
		return "malformed json", nil
	})
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		return true
	})

	rpc := startRPCMock(dispatcher)
	defer stopRPCMock(rpc)

	count := syncAPISpecs()
	if count != 0 {
		t.Error("Should return empty value for malformed rpc response", apiSpecs)
	}
}

func TestSyncAPISpecsRPCSuccess(t *testing.T) {
	// Mock RPC
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *DefRequest) (string, error) {
		return "[{}]", nil
	})
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		return true
	})

	rpc := startRPCMock(dispatcher)
	defer stopRPCMock(rpc)

	count := syncAPISpecs()
	if count != 1 {
		t.Error("Should return array with one spec", apiSpecs)
	}
}

func TestSyncAPISpecsDashboardSuccess(t *testing.T) {
	// Mock Dashboard
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/system/apis" {
			w.Write([]byte(`{"Status": "OK", "Nonce": "1", "Message": [{"api_definition": {}}]}`))
		} else {
			t.Fatal("Unknown dashboard API request", r)
		}
	}))
	defer ts.Close()

	apisMu.Lock()
	apisByID = make(map[string]*APISpec)
	apisMu.Unlock()

	config.Global.UseDBAppConfigs = true
	config.Global.AllowInsecureConfigs = true
	config.Global.DBAppConfOptions.ConnectionString = ts.URL

	defer func() {
		config.Global.UseDBAppConfigs = false
		config.Global.AllowInsecureConfigs = false
		config.Global.DBAppConfOptions.ConnectionString = ""
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	msg := redis.Message{Data: []byte(`{"Command": "ApiUpdated"}`)}
	handled := func(got NotificationCommand) {
		if want := NoticeApiUpdated; got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	handleRedisEvent(msg, handled, wg.Done)

	// Since we already know that reload is queued
	reloadTick <- time.Time{}

	// Wait for the reload to finish, then check it worked
	wg.Wait()
	apisMu.RLock()
	if len(apisByID) != 1 {
		t.Error("Should return array with one spec", apisByID)
	}
	apisMu.RUnlock()
}

func TestRoundRobin(t *testing.T) {
	rr := RoundRobin{}
	for _, want := range []int{0, 1, 2, 0} {
		if got := rr.WithLen(3); got != want {
			t.Errorf("RR Pos wrong: want %d got %d", want, got)
		}
	}
	if got, want := rr.WithLen(0), 0; got != want {
		t.Errorf("RR Pos of 0 wrong: want %d got %d", want, got)
	}
}

func setupKeepalive(conn net.Conn) error {
	tcpConn := conn.(*net.TCPConn)
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return err
	}
	if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
		return err
	}
	return nil
}

type customListener struct {
	L net.Listener
}

func (ln *customListener) Init(addr string) (err error) {
	ln.L, err = net.Listen("tcp", addr)
	return
}

func (ln *customListener) Accept() (conn io.ReadWriteCloser, clientAddr string, err error) {
	c, err := ln.L.Accept()
	if err != nil {
		return
	}

	if err = setupKeepalive(c); err != nil {
		c.Close()
		return
	}

	handshake := make([]byte, 6)
	if _, err = io.ReadFull(c, handshake); err != nil {
		return
	}

	idLenBuf := make([]byte, 1)
	if _, err = io.ReadFull(c, idLenBuf); err != nil {
		return
	}

	idLen := uint8(idLenBuf[0])
	id := make([]byte, idLen)
	if _, err = io.ReadFull(c, id); err != nil {
		return
	}

	return c, string(id), nil
}

func (ln *customListener) Close() error {
	return ln.L.Close()
}
