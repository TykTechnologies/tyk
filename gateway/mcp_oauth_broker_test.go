package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

type mcpOAuthBrokerUpstreamCapture struct {
	mu                   sync.Mutex
	metadataHeaders      []http.Header
	registrationHeaders  []http.Header
	registeredRedirects  []string
	registeredClientID   string
	registrationRequests int
}

func newMCPBrokerTest(t *testing.T, listenPath string) (*Test, *httptest.Server, *mcpOAuthBrokerUpstreamCapture) {
	t.Helper()
	capture := &mcpOAuthBrokerUpstreamCapture{registeredClientID: "upstream-public-client"}
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(upstream.Close)
	upstreamResource := upstream.URL + "/v1/mcp"
	upstream.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/v1/mcp":
			capture.mu.Lock()
			capture.metadataHeaders = append(capture.metadataHeaders, r.Header.Clone())
			capture.mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"resource":%q,"authorization_servers":[%q]}`, upstreamResource, upstream.URL)
		case "/.well-known/oauth-authorization-server":
			capture.mu.Lock()
			capture.metadataHeaders = append(capture.metadataHeaders, r.Header.Clone())
			capture.mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"registration_endpoint":%q,"scopes_supported":["mcp"],"service_documentation":"https://docs.example/mcp","signed_metadata":"must-not-copy"}`,
				upstream.URL, upstream.URL+"/authorize", upstream.URL+"/token", upstream.URL+"/register")
		case "/register":
			capture.mu.Lock()
			capture.registrationRequests++
			capture.registrationHeaders = append(capture.registrationHeaders, r.Header.Clone())
			var registration struct {
				RedirectURIs []string `json:"redirect_uris"`
			}
			_ = json.NewDecoder(r.Body).Decode(&registration)
			capture.registeredRedirects = append([]string(nil), registration.RedirectURIs...)
			capture.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"token_endpoint_auth_method":"none"}`, capture.registeredClientID)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	doc := oas.OAS{T: openapi3.T{OpenAPI: "3.0.3", Info: &openapi3.Info{Title: "broker", Version: "1"}, Paths: openapi3.NewPaths()}}
	doc.SetTykExtension(&oas.XTykAPIGateway{
		Info:     oas.Info{Name: "broker", State: oas.State{Active: true}},
		Upstream: oas.Upstream{URL: upstreamResource},
		Server: oas.Server{
			ListenPath:     oas.ListenPath{Value: listenPath, Strip: true},
			Authentication: &oas.Authentication{ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{Enabled: true}},
		},
	})
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.MarkAsMCP()
		spec.Proxy.ListenPath = listenPath
		spec.Proxy.TargetURL = upstreamResource
		spec.IsOAS = true
		spec.OAS = doc
		spec.MCP = &apidef.MCPConfig{OAuthBroker: &apidef.MCPOAuthBrokerConfig{
			Enabled: true, PublicOrigin: ts.URL, PublicResource: ts.URL + listenPath,
			UpstreamResource: upstreamResource, AllowInsecureLoopback: true,
		}}
	})
	ts.Gw.PRMCache().Invalidate(upstream.URL + "/.well-known/oauth-protected-resource/v1/mcp")
	return ts, upstream, capture
}

func TestMCPOAuthBrokerMetadataAndRootRoutes(t *testing.T) {
	for _, listenPath := range []string{"/mcp/", "/"} {
		t.Run(listenPath, func(t *testing.T) {
			ts, _, capture := newMCPBrokerTest(t, listenPath)
			prmPath := "/.well-known/oauth-protected-resource" + strings.TrimRight(listenPath, "/")
			if listenPath == "/" {
				prmPath = "/.well-known/oauth-protected-resource"
			}
			prmResponse, _ := ts.Run(t, test.TestCase{Method: http.MethodGet, Path: prmPath, Code: http.StatusOK})
			var prm map[string]any
			require.NoError(t, json.NewDecoder(prmResponse.Body).Decode(&prm))
			require.Equal(t, ts.URL+listenPath, prm["resource"])
			require.Equal(t, []any{ts.URL + "/__tyk-as/test"}, prm["authorization_servers"])
			for _, path := range []string{
				"/.well-known/oauth-authorization-server/__tyk-as/test",
				"/__tyk-as/test/.well-known/oauth-authorization-server",
			} {
				response, _ := ts.Run(t, test.TestCase{Method: http.MethodGet, Path: path, Code: http.StatusOK})
				var metadata map[string]any
				require.NoError(t, json.NewDecoder(response.Body).Decode(&metadata))
				require.Equal(t, ts.URL+"/__tyk-as/test", metadata["issuer"])
				require.Equal(t, ts.URL+"/__tyk-as/test/register", metadata["registration_endpoint"])
				require.Equal(t, "https://docs.example/mcp", metadata["service_documentation"])
				require.NotContains(t, metadata, "signed_metadata")
			}

			request, err := http.NewRequest(http.MethodGet, ts.URL+"/.well-known/oauth-authorization-server/__tyk-as/test", nil)
			require.NoError(t, err)
			request.Host = "attacker.example"
			response, err := http.DefaultClient.Do(request)
			require.NoError(t, err)
			_ = response.Body.Close()
			require.Equal(t, http.StatusBadRequest, response.StatusCode)

			request, err = http.NewRequest(http.MethodGet, ts.URL+"/.well-known/oauth-authorization-server/__tyk-as/test", nil)
			require.NoError(t, err)
			request.Header.Set("Forwarded", `for=192.0.2.1;proto=https;host=attacker.example`)
			request.Header.Set("X-Forwarded-Host", "attacker.example")
			response, err = http.DefaultClient.Do(request)
			require.NoError(t, err)
			defer response.Body.Close()
			require.Equal(t, http.StatusOK, response.StatusCode, "untrusted forwarding headers must not become authority")

			capture.mu.Lock()
			defer capture.mu.Unlock()
			for _, headers := range capture.metadataHeaders {
				require.Empty(t, headers.Get("Authorization"))
				require.Empty(t, headers.Get("MCP-Protocol-Version"))
				require.Equal(t, "application/json", headers.Get("Accept"))
			}
		})
	}
}

func registerMCPBrokerClient(t *testing.T, ts *Test, redirectURI string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"redirect_uris": []string{redirectURI}, "token_endpoint_auth_method": "none", "client_name": "fixture",
	})
	require.NoError(t, err)
	response, _ := ts.Run(t, test.TestCase{
		Method: http.MethodPost, Path: "/__tyk-as/test/register", Data: string(body),
		Headers: map[string]string{"Content-Type": "application/json"}, Code: http.StatusCreated,
	})
	var registration map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&registration))
	clientID, _ := registration["client_id"].(string)
	require.NotEmpty(t, clientID)
	require.NotEqual(t, "upstream-public-client", clientID)
	return clientID
}

func TestMCPOAuthBrokerDCRAndAuthorizeFoundation(t *testing.T) {
	ts, _, capture := newMCPBrokerTest(t, "/mcp/")
	redirectURI := "https://client.example/callback?kept=yes"
	clientID := registerMCPBrokerClient(t, ts, redirectURI)

	capture.mu.Lock()
	require.Equal(t, []string{ts.URL + "/__tyk-as/test/callback"}, capture.registeredRedirects)
	require.Len(t, capture.registrationHeaders, 1)
	require.Empty(t, capture.registrationHeaders[0].Get("Authorization"))
	require.Empty(t, capture.registrationHeaders[0].Get("MCP-Protocol-Version"))
	capture.mu.Unlock()

	challenge := strings.Repeat("a", 43)
	query := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"state": {"downstream-state"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"resource": {ts.URL + "/mcp/"}, "scope": {"mcp"},
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(ts.URL + "/__tyk-as/test/authorize?" + query.Encode())
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusFound, response.StatusCode)
	location, err := response.Location()
	require.NoError(t, err)
	require.Equal(t, "upstream-public-client", location.Query().Get("client_id"))
	require.Equal(t, ts.URL+"/__tyk-as/test/callback", location.Query().Get("redirect_uri"))
	require.Equal(t, "mcp", location.Query().Get("scope"))
	require.NotEqual(t, "downstream-state", location.Query().Get("state"))
	require.Equal(t, "S256", location.Query().Get("code_challenge_method"))
	require.NotEqual(t, challenge, location.Query().Get("code_challenge"))

	store := newRedisMCPOAuthBrokerStore(ts.Gw)
	stateRaw, found, err := store.Get(context.Background(), mcpOAuthBrokerKey("state", "default", "test", location.Query().Get("state")))
	require.NoError(t, err)
	require.True(t, found)
	var state mcpOAuthAuthorizationState
	require.NoError(t, json.Unmarshal(stateRaw, &state))
	require.Equal(t, "downstream-state", state.OriginalState)
	require.Equal(t, challenge, state.DownstreamChallenge)
	require.Len(t, state.UpstreamVerifier, 43)
	require.NotContains(t, string(stateRaw), "attacker")
}

func TestMCPOAuthBrokerDCRAndAuthorizeRejectAmbiguity(t *testing.T) {
	ts, _, capture := newMCPBrokerTest(t, "/mcp/")
	for _, body := range []string{
		`{"redirect_uris":["https://client.example/cb"],"Redirect_URIs":["https://attacker.example/cb"],"token_endpoint_auth_method":"none"}`,
		`{"redirect_uris":["https://client.example/cb?code=attacker"],"token_endpoint_auth_method":"none"}`,
		`{"redirect_uris":["http://client.example/cb"],"token_endpoint_auth_method":"none"}`,
		`{"redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		`{"redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"none","response_types":["token"]}`,
		`{"redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"none","grant_types":["implicit"]}`,
	} {
		response, _ := ts.Run(t, test.TestCase{
			Method: http.MethodPost, Path: "/__tyk-as/test/register", Data: body,
			Headers: map[string]string{"Content-Type": "application/json"}, Code: http.StatusBadRequest,
		})
		_ = response.Body.Close()
	}
	capture.mu.Lock()
	require.Zero(t, capture.registrationRequests)
	capture.mu.Unlock()

	clientID := registerMCPBrokerClient(t, ts, "https://client.example/cb")
	base := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://client.example/cb"},
		"state": {"state"}, "code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"},
		"resource": {ts.URL + "/mcp/"}, "scope": {"mcp"},
	}
	for name, mutate := range map[string]func(url.Values){
		"duplicate state":   func(values url.Values) { values["state"] = []string{"one", "two"} },
		"wrong resource":    func(values url.Values) { values.Set("resource", "https://attacker.example/mcp") },
		"unknown client":    func(values url.Values) { values.Set("client_id", "unknown") },
		"unsupported scope": func(values url.Values) { values.Set("scope", "admin") },
		"foreign callback":  func(values url.Values) { values.Set("redirect_uri", "https://attacker.example/cb") },
	} {
		t.Run(name, func(t *testing.T) {
			values := cloneURLValues(base)
			mutate(values)
			response, _ := ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/__tyk-as/test/authorize?" + values.Encode(), Code: http.StatusBadRequest})
			_ = response.Body.Close()
		})
	}
}

func cloneURLValues(source url.Values) url.Values {
	result := make(url.Values, len(source))
	for key, values := range source {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func TestRedisMCPOAuthBrokerStoreAtomicConsume(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	storeA := newRedisMCPOAuthBrokerStore(ts.Gw)
	storeB := newRedisMCPOAuthBrokerStore(ts.Gw)
	key, err := randomMCPOAuthValue()
	require.NoError(t, err)
	require.NoError(t, storeA.Put(context.Background(), key, []byte("secret-state"), time.Minute))
	value, found, err := storeB.Get(context.Background(), key)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []byte("secret-state"), value)

	var winners atomic.Int64
	var wait sync.WaitGroup
	errorsFound := make(chan error, 16)
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func(store mcpOAuthBrokerStore) {
			defer wait.Done()
			value, found, err := store.Consume(context.Background(), key)
			if err != nil {
				errorsFound <- err
				return
			}
			if found {
				if string(value) != "secret-state" {
					errorsFound <- fmt.Errorf("unexpected consumed value %q", value)
					return
				}
				winners.Add(1)
			}
		}(map[bool]mcpOAuthBrokerStore{true: storeA, false: storeB}[index%2 == 0])
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, winners.Load())
}

func TestTrustedMCPOAuthEndpoint(t *testing.T) {
	for _, test := range []struct {
		name, issuer, endpoint string
		allowLoopback, want    bool
	}{
		{name: "same HTTPS authority", issuer: "https://as.example/tenant", endpoint: "https://as.example/token", want: true},
		{name: "cross authority", issuer: "https://as.example", endpoint: "https://attacker.example/token"},
		{name: "userinfo", issuer: "https://as.example", endpoint: "https://user@as.example/token"},
		{name: "query", issuer: "https://as.example", endpoint: "https://as.example/token?next=attacker"},
		{name: "loopback explicit", issuer: "http://127.0.0.1:8080", endpoint: "http://127.0.0.1:8080/token", allowLoopback: true, want: true},
		{name: "loopback disabled", issuer: "http://127.0.0.1:8080", endpoint: "http://127.0.0.1:8080/token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, trustedMCPOAuthEndpoint(test.issuer, test.endpoint, test.allowLoopback))
		})
	}
}

func TestFetchUpstreamASMetadataStrictBoundsAndIssuer(t *testing.T) {
	var header http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
		_, _ = io.WriteString(w, strings.Repeat("x", maxUpstreamASMetadataBytes+1))
	}))
	_, err := fetchUpstreamASMetadata(context.Background(), server.URL)
	server.Close()
	require.ErrorContains(t, err, "exceeds")
	require.Empty(t, header.Get("MCP-Protocol-Version"))
	require.Equal(t, "application/json", header.Get("Accept"))

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"issuer":"https://wrong.example"}`)
	}))
	defer server.Close()
	_, err = fetchUpstreamASMetadata(context.Background(), server.URL)
	require.ErrorContains(t, err, "does not exactly match")
}

func TestMCPOAuthBrokerDoesNotExposeIncompleteTokenOrCallback(t *testing.T) {
	ts, _, _ := newMCPBrokerTest(t, "/mcp/")
	for _, request := range []test.TestCase{
		{Method: http.MethodGet, Path: "/__tyk-as/test/callback", Code: http.StatusNotImplemented},
		{Method: http.MethodPost, Path: "/__tyk-as/test/token", Data: url.Values{"grant_type": {"authorization_code"}}.Encode(), Code: http.StatusNotImplemented},
	} {
		response, _ := ts.Run(t, request)
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		require.NotContains(t, string(body), "upstream")
	}
}
