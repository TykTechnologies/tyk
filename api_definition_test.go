package main

import (
	"encoding/json"
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

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func createDefinitionFromString(defStr string) *APISpec {
	loader := APIDefinitionLoader{}
	def := loader.ParseDefinition(strings.NewReader(defStr))
	spec := loader.MakeSpec(def)
	return spec
}

func TestWhitelist(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				json.Unmarshal([]byte(`[
					{
						"path": "/reply/{id}",
						"method_actions": {
							"GET": {"action": "reply", "code": 200, "data": "flump"}
						}
					},
					{
						"path": "/get",
						"method_actions": {"GET": {"action": "no_action"}}
					}
				]`), &v.ExtendedPaths.WhiteList)
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			// Should mock path
			{Path: "/reply/", Code: 200, BodyMatch: "flump"},
			{Path: "/reply/123", Code: 200, BodyMatch: "flump"},
			// Should get original upstream response
			{Path: "/get", Code: 200, BodyMatch: `"Url":"/get"`},
			// Reject not whitelisted (but know by upstream) path
			{Method: "POST", Path: "/post", Code: 403},
		}...)
	})

	t.Run("Simple Paths", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.WhiteList = []string{"/simple", "/regex/{id}/test"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			// Should mock path
			{Path: "/simple", Code: 200},
			{Path: "/regex/123/test", Code: 200},
			{Path: "/regex/123/differ", Code: 403},
			{Path: "/", Code: 403},
		}...)
	})
}

func TestBlacklist(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				json.Unmarshal([]byte(`[
					{
						"path": "/blacklist/literal",
						"method_actions": {"GET": {"action": "no_action"}}
					},
					{
						"path": "/blacklist/{id}/test",
						"method_actions": {"GET": {"action": "no_action"}}
					}
				]`), &v.ExtendedPaths.BlackList)
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/blacklist/literal", Code: 403},
			{Path: "/blacklist/123/test", Code: 403},

			{Path: "/blacklist/123/different", Code: 200},
			// POST method not blacklisted
			{Method: "POST", Path: "/blacklist/literal", Code: 200},
		}...)
	})

	t.Run("Simple Paths", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.BlackList = []string{"/blacklist/literal", "/blacklist/{id}/test"}
				v.UseExtendedPaths = false
			})

			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/blacklist/literal", Code: 403},
			{Path: "/blacklist/123/test", Code: 403},

			{Path: "/blacklist/123/different", Code: 200},
			// POST method also blacklisted
			{Method: "POST", Path: "/blacklist/literal", Code: 403},
		}...)
	})
}

func TestIgnored(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	t.Run("Extended Paths", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				json.Unmarshal([]byte(`[
					{
						"path": "/ignored/literal",
						"method_actions": {"GET": {"action": "no_action"}}
					},
					{
						"path": "/ignored/{id}/test",
						"method_actions": {"GET": {"action": "no_action"}}
					}
				]`), &v.ExtendedPaths.Ignored)
			})

			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			// Should ignore auth check
			{Path: "/ignored/literal", Code: 200},
			{Path: "/ignored/123/test", Code: 200},
			// Only GET is ignored
			{Method: "POST", Path: "/ext/ignored/literal", Code: 401},

			{Path: "/", Code: 401},
		}...)
	})

	t.Run("Simple Paths", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.Paths.Ignored = []string{"/ignored/literal", "/ignored/{id}/test"}
				v.UseExtendedPaths = false
			})

			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			// Should ignore auth check
			{Path: "/ignored/literal", Code: 200},
			{Path: "/ignored/123/test", Code: 200},
			// All methods ignored
			{Method: "POST", Path: "/ext/ignored/literal", Code: 200},

			{Path: "/", Code: 401},
		}...)
	})
}

func startRPCMock(dispatcher *gorpc.Dispatcher) *gorpc.Server {
	configMu.Lock()
	defer configMu.Unlock()

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
