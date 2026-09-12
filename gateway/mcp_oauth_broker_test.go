package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

type faultingMCPOAuthBrokerStore struct {
	mcpOAuthBrokerStore
	getPrefix string
	putPrefix string
}

func (s faultingMCPOAuthBrokerStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if strings.HasPrefix(key, s.getPrefix) && s.getPrefix != "" {
		return nil, false, errors.New("injected OAuth broker get failure")
	}
	return s.mcpOAuthBrokerStore.Get(ctx, key)
}

func (s faultingMCPOAuthBrokerStore) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if strings.HasPrefix(key, s.putPrefix) && s.putPrefix != "" {
		return errors.New("injected OAuth broker put failure")
	}
	return s.mcpOAuthBrokerStore.Put(ctx, key, value, ttl)
}

type mcpOAuthBrokerUpstreamCapture struct {
	mu                    sync.Mutex
	metadataHeaders       []http.Header
	registrationHeaders   []http.Header
	registeredRedirects   []string
	registeredClientID    string
	registrationRequests  int
	authorizationRequests int
	tokenRequests         int
	runtimeRequests       int
	lastTokenForm         url.Values
	lastRuntimeAuth       string
	lastRuntimePath       string
	codeChallenges        map[string]string
	refreshToken          string
}

func newMCPBrokerTest(t *testing.T, listenPath string) (*Test, *httptest.Server, *mcpOAuthBrokerUpstreamCapture) {
	t.Helper()
	capture := &mcpOAuthBrokerUpstreamCapture{
		registeredClientID: "upstream-public-client",
		codeChallenges:     map[string]string{},
		refreshToken:       "upstream-refresh-1",
	}
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
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"registration_endpoint":%q,"scopes_supported":["mcp"],"authorization_response_iss_parameter_supported":true,"service_documentation":"https://docs.example/mcp","signed_metadata":"must-not-copy"}`,
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
		case "/authorize":
			capture.mu.Lock()
			capture.authorizationRequests++
			code := fmt.Sprintf("upstream-code-%d", capture.authorizationRequests)
			capture.codeChallenges[code] = r.URL.Query().Get("code_challenge")
			capture.mu.Unlock()
			target, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
			query := target.Query()
			query.Set("code", code)
			query.Set("state", r.URL.Query().Get("state"))
			query.Set("iss", upstream.URL)
			target.RawQuery = query.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
		case "/token":
			_ = r.ParseForm()
			capture.mu.Lock()
			capture.tokenRequests++
			capture.lastTokenForm = cloneURLValues(r.PostForm)
			grantType := r.PostForm.Get("grant_type")
			if grantType == "authorization_code" {
				challenge := capture.codeChallenges[r.PostForm.Get("code")]
				if challenge == "" || mcpOAuthPKCEChallenge(r.PostForm.Get("code_verifier")) != challenge {
					capture.mu.Unlock()
					w.WriteHeader(http.StatusBadRequest)
					_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
					return
				}
			} else if grantType != "refresh_token" || r.PostForm.Get("refresh_token") != capture.refreshToken {
				capture.mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
			access := fmt.Sprintf("upstream-access-%d", capture.tokenRequests)
			capture.refreshToken = fmt.Sprintf("upstream-refresh-%d", capture.tokenRequests+1)
			refresh := capture.refreshToken
			capture.mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":3600,"refresh_token":%q,"scope":"mcp"}`, access, refresh)
		case "/", "/v1/mcp", "/v1/mcp/":
			capture.mu.Lock()
			capture.runtimeRequests++
			capture.lastRuntimeAuth = r.Header.Get("Authorization")
			capture.lastRuntimePath = r.URL.RequestURI()
			capture.mu.Unlock()
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`)
		default:
			if r.Method == http.MethodPost {
				capture.mu.Lock()
				capture.runtimeRequests++
				capture.lastRuntimeAuth = r.Header.Get("Authorization")
				capture.lastRuntimePath = r.URL.RequestURI()
				capture.mu.Unlock()
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`)
				return
			}
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
		spec.Proxy.StripListenPath = true
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
	require.NotContains(t, string(stateRaw), "downstream-state")
	require.NotContains(t, string(stateRaw), challenge)
	var state mcpOAuthAuthorizationState
	broker := newMCPOAuthBroker(ts.Gw, ts.Gw.getApiSpec("test"))
	require.NoError(t, broker.openRecord(mcpOAuthBrokerKey("state", "default", "test", location.Query().Get("state")), stateRaw, &state))
	require.Equal(t, "downstream-state", state.OriginalState)
	require.Equal(t, challenge, state.DownstreamChallenge)
	require.Len(t, state.UpstreamVerifier, 43)
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

type mcpBrokerTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
}

func runMCPBrokerAuthorization(t *testing.T, ts *Test, redirectURI, clientState string) (string, string, string) {
	t.Helper()
	clientID := registerMCPBrokerClient(t, ts, redirectURI)
	verifier := strings.Repeat("v", 43)
	query := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"state": {clientState}, "code_challenge": {mcpOAuthPKCEChallenge(verifier)}, "code_challenge_method": {"S256"},
		"resource": {ts.URL + "/mcp/"}, "scope": {"mcp"},
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authorize, err := client.Get(ts.URL + "/__tyk-as/test/authorize?" + query.Encode())
	require.NoError(t, err)
	_ = authorize.Body.Close()
	require.Equal(t, http.StatusFound, authorize.StatusCode)
	upstreamAuthorize, err := authorize.Location()
	require.NoError(t, err)
	upstreamResponse, err := client.Get(upstreamAuthorize.String())
	require.NoError(t, err)
	_ = upstreamResponse.Body.Close()
	require.Equal(t, http.StatusFound, upstreamResponse.StatusCode)
	callback, err := upstreamResponse.Location()
	require.NoError(t, err)
	callbackResponse, err := client.Get(callback.String())
	require.NoError(t, err)
	_ = callbackResponse.Body.Close()
	require.Equal(t, http.StatusFound, callbackResponse.StatusCode)
	downstream, err := callbackResponse.Location()
	require.NoError(t, err)
	require.Equal(t, redirectURI, downstream.Scheme+"://"+downstream.Host+downstream.Path)
	require.Equal(t, clientState, downstream.Query().Get("state"))
	require.Equal(t, ts.URL+"/__tyk-as/test", downstream.Query().Get("iss"))
	require.NotEmpty(t, downstream.Query().Get("code"))
	return clientID, verifier, downstream.Query().Get("code")
}

func exchangeMCPBrokerToken(t *testing.T, ts *Test, form url.Values, wantStatus int) mcpBrokerTokens {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, ts.URL+"/__tyk-as/test/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, wantStatus, response.StatusCode)
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	require.Equal(t, "no-cache", response.Header.Get("Pragma"))
	var tokens mcpBrokerTokens
	if wantStatus == http.StatusOK {
		require.NoError(t, json.NewDecoder(response.Body).Decode(&tokens))
	}
	return tokens
}

func TestMCPOAuthBrokerCallbackTokenRuntimeAndRefresh(t *testing.T) {
	ts, _, capture := newMCPBrokerTest(t, "/mcp/")
	logger, hook := logrustest.NewNullLogger()
	originalLog := log
	log = logger
	t.Cleanup(func() { log = originalLog })
	redirectURI := "https://client.example/callback"
	clientID, verifier, code := runMCPBrokerAuthorization(t, ts, redirectURI, "client-state")
	tokens := exchangeMCPBrokerToken(t, ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}, "resource": {ts.URL + "/mcp/"},
	}, http.StatusOK)
	require.Equal(t, "Bearer", tokens.TokenType)
	require.Equal(t, "mcp", tokens.Scope)
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken)
	require.Positive(t, tokens.ExpiresIn)
	require.NotContains(t, tokens.AccessToken, "upstream")
	require.NotContains(t, tokens.RefreshToken, "upstream")

	spec := ts.Gw.getApiSpec("test")
	middleware := &MCPOAuthBrokerTokenMiddleware{BaseMiddleware: &BaseMiddleware{Gw: ts.Gw, Spec: spec}}
	inbound := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	inbound.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	err, status := middleware.ProcessRequest(httptest.NewRecorder(), inbound, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "Bearer "+tokens.AccessToken, inbound.Header.Get("Authorization"), "inbound analytics value must remain the downstream token")
	outbound := inbound.Clone(inbound.Context())
	outbound.URL, err = url.Parse(spec.MCP.OAuthBroker.UpstreamResource)
	require.NoError(t, err)
	(&ReverseProxy{TykAPISpec: spec, Gw: ts.Gw}).addAuthInfo(outbound, inbound)
	capture.mu.Lock()
	expectedUpstream := fmt.Sprintf("Bearer upstream-access-%d", capture.tokenRequests)
	capture.mu.Unlock()
	require.Equal(t, expectedUpstream, outbound.Header.Get("Authorization"))
	require.NotContains(t, outbound.Header.Get("Authorization"), tokens.AccessToken)

	spec.EnableDetailedRecording = true
	analyticsRecord := captureAnalytics(ts)
	runtimeResponse, _ := ts.Run(t, test.TestCase{
		Method: http.MethodPost, Path: "/mcp/", Code: http.StatusOK,
		Data: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"broker-test","version":"1"},"capabilities":{}}}`,
		Headers: map[string]string{
			"Authorization": "Bearer " + tokens.AccessToken,
			"Content-Type":  "application/json",
			"Accept":        "application/json, text/event-stream",
		},
	})
	runtimeBody, err := io.ReadAll(runtimeResponse.Body)
	require.NoError(t, err)
	_ = runtimeResponse.Body.Close()
	require.NotContains(t, string(runtimeBody), "upstream-access")
	capture.mu.Lock()
	require.Equal(t, expectedUpstream, capture.lastRuntimeAuth, "final runtime target %s", capture.lastRuntimePath)
	require.Equal(t, 1, capture.runtimeRequests)
	capture.mu.Unlock()
	record := analyticsRecord.Load()
	require.NotNil(t, record)
	require.Equal(t, "test", record.APIID)
	require.Equal(t, "default", record.OrgID)
	require.Equal(t, http.StatusOK, record.ResponseCode)
	rawRequest, err := base64.StdEncoding.DecodeString(record.RawRequest)
	require.NoError(t, err)
	require.Contains(t, string(rawRequest), "Authorization: "+obfuscationToken)

	rotated := exchangeMCPBrokerToken(t, ts, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
		"client_id": {clientID}, "resource": {ts.URL + "/mcp/"},
	}, http.StatusOK)
	require.NotEqual(t, tokens.AccessToken, rotated.AccessToken)
	require.NotEqual(t, tokens.RefreshToken, rotated.RefreshToken)

	exchangeMCPBrokerToken(t, ts, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
		"client_id": {clientID}, "resource": {ts.URL + "/mcp/"},
	}, http.StatusBadRequest)
	capture.mu.Lock()
	requestsBeforeRevokedRefresh := capture.tokenRequests
	capture.mu.Unlock()
	exchangeMCPBrokerToken(t, ts, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rotated.RefreshToken},
		"client_id": {clientID}, "resource": {ts.URL + "/mcp/"},
	}, http.StatusBadRequest)
	capture.mu.Lock()
	require.Equal(t, requestsBeforeRevokedRefresh, capture.tokenRequests,
		"a revoked family must be rejected before an upstream refresh exchange")
	capture.mu.Unlock()
	err, status = middleware.ProcessRequest(httptest.NewRecorder(), inbound, nil)
	require.Error(t, err)
	require.Equal(t, http.StatusUnauthorized, status, "refresh replay revokes the token family")

	broker := newMCPOAuthBroker(ts.Gw, spec)
	sealedGrant, found, err := broker.store.Get(context.Background(), broker.accessKey(tokens.AccessToken))
	require.NoError(t, err)
	require.True(t, found)
	require.NotContains(t, string(sealedGrant), "upstream-access")
	require.NotContains(t, string(sealedGrant), "upstream-refresh")

	logBytes, err := json.Marshal(hook.AllEntries())
	require.NoError(t, err)
	analyticsBytes, err := json.Marshal(record)
	require.NoError(t, err)
	boundedEvidence := string(logBytes) + string(analyticsBytes) + string(rawRequest) + string(runtimeBody) + string(sealedGrant)
	for _, secret := range []string{
		tokens.AccessToken, tokens.RefreshToken, rotated.AccessToken, rotated.RefreshToken,
		code, verifier, clientID, "upstream-access-1", "upstream-access-2",
		"upstream-refresh-2", "upstream-refresh-3", "upstream-registration-management-bearer",
	} {
		require.NotContains(t, boundedEvidence, secret)
	}
	require.Contains(t, boundedEvidence, "test")
	require.Contains(t, boundedEvidence, "default")
}

func TestMCPOAuthBearerProviderFinalTargetBinding(t *testing.T) {
	provider, err := newMCPOAuthBearerProvider("https://trusted.example/v1/mcp", "upstream-secret")
	require.NoError(t, err)

	for _, tc := range []struct {
		name, target string
		wantBearer   bool
	}{
		{name: "exact resource", target: "https://trusted.example/v1/mcp", wantBearer: true},
		{name: "trailing slash mismatch", target: "https://trusted.example/v1/mcp/"},
		{name: "scheme rewrite", target: "http://trusted.example/v1/mcp"},
		{name: "authority rewrite", target: "https://attacker.example/v1/mcp"},
		{name: "path prefix", target: "https://trusted.example/v1/mcp/child"},
		{name: "path sibling", target: "https://trusted.example/v1/other"},
		{name: "query rewrite", target: "https://trusted.example/v1/mcp?next=attacker"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, tc.target, nil)
			request.Header.Set(header.Authorization, "Bearer downstream-secret")
			provider.Fill(request)
			if tc.wantBearer {
				require.Equal(t, "Bearer upstream-secret", request.Header.Get(header.Authorization))
			} else {
				require.Empty(t, request.Header.Get(header.Authorization))
			}
		})
	}
	trailingProvider, err := newMCPOAuthBearerProvider("https://trusted.example/v1/mcp/", "upstream-secret")
	require.NoError(t, err)
	withoutSlash := httptest.NewRequest(http.MethodPost, "https://trusted.example/v1/mcp", nil)
	withoutSlash.Header.Set(header.Authorization, "Bearer downstream-secret")
	trailingProvider.Fill(withoutSlash)
	require.Empty(t, withoutSlash.Header.Get(header.Authorization), "missing trailing slash must be an exact-path mismatch")
}

func TestMCPOAuthRefreshStoreFailuresFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		getPrefix  string
		putPrefix  string
		preconsume bool
	}{
		{name: "revocation marker read", getPrefix: "revoked-family:"},
		{name: "refresh family lookup", getPrefix: "refresh-family:", preconsume: true},
		{name: "revocation marker write", putPrefix: "revoked-family:", preconsume: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, _, capture := newMCPBrokerTest(t, "/mcp/")
			redirectURI := "https://client.example/callback"
			clientID, verifier, code := runMCPBrokerAuthorization(t, ts, redirectURI, "storage-state")
			tokens := exchangeMCPBrokerToken(t, ts, url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
				"redirect_uri": {redirectURI}, "code_verifier": {verifier}, "resource": {ts.URL + "/mcp/"},
			}, http.StatusOK)
			broker := newMCPOAuthBroker(ts.Gw, ts.Gw.getApiSpec("test"))
			if tc.preconsume {
				var grant mcpOAuthTokenGrant
				found, err := broker.consumeRecord(context.Background(), broker.refreshKey(tokens.RefreshToken), &grant)
				require.NoError(t, err)
				require.True(t, found)
			}
			broker.store = faultingMCPOAuthBrokerStore{
				mcpOAuthBrokerStore: broker.store, getPrefix: tc.getPrefix, putPrefix: tc.putPrefix,
			}
			capture.mu.Lock()
			requestsBefore := capture.tokenRequests
			capture.mu.Unlock()
			form := url.Values{
				"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
				"client_id": {clientID}, "resource": {ts.URL + "/mcp/"},
			}
			request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
			response := httptest.NewRecorder()
			broker.refreshToken(response, request, form)
			require.Equal(t, http.StatusServiceUnavailable, response.Code)
			capture.mu.Lock()
			require.Equal(t, requestsBefore, capture.tokenRequests, "storage failures must prevent upstream exchange")
			capture.mu.Unlock()
		})
	}
}

func TestMCPOAuthBrokerRejectsAmbiguousUpstreamAuthentication(t *testing.T) {
	ts, _, _ := newMCPBrokerTest(t, "/mcp/")
	spec := ts.Gw.getApiSpec("test")
	spec.UpstreamAuth = apidef.UpstreamAuth{
		Enabled: true, BasicAuth: apidef.UpstreamBasicAuth{Enabled: true},
	}
	require.ErrorContains(t, spec.Validate(config.OASConfig{}), "cannot be combined")
	require.False(t, shouldLoadGenericUpstreamAuth(spec), "broker mode must suppress later generic upstream auth middleware")
}

func TestMCPOAuthBrokerCallbackRejectsIssuerAndReplay(t *testing.T) {
	ts, upstream, _ := newMCPBrokerTest(t, "/mcp/")
	clientID := registerMCPBrokerClient(t, ts, "https://client.example/callback")
	query := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://client.example/callback"},
		"state": {"client-state"}, "code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"},
		"resource": {ts.URL + "/mcp/"}, "scope": {"mcp"},
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authorize, err := client.Get(ts.URL + "/__tyk-as/test/authorize?" + query.Encode())
	require.NoError(t, err)
	_ = authorize.Body.Close()
	location, err := authorize.Location()
	require.NoError(t, err)
	state := location.Query().Get("state")

	badIssuer := ts.URL + "/__tyk-as/test/callback?" + url.Values{
		"state": {state}, "code": {"upstream-code"}, "iss": {upstream.URL + "/wrong"},
	}.Encode()
	response, err := client.Get(badIssuer)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusBadRequest, response.StatusCode)

	replay := ts.URL + "/__tyk-as/test/callback?" + url.Values{
		"state": {state}, "code": {"upstream-code"}, "iss": {upstream.URL},
	}.Encode()
	response, err = client.Get(replay)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
}

func TestMCPOAuthBrokerCallbackForwardsProviderErrorWithPublicIdentity(t *testing.T) {
	ts, upstream, capture := newMCPBrokerTest(t, "/mcp/")
	logger, hook := logrustest.NewNullLogger()
	originalLog := log
	log = logger
	t.Cleanup(func() { log = originalLog })
	analyticsRecord := captureAnalytics(ts)
	redirectURI := "https://client.example/callback"
	clientID := registerMCPBrokerClient(t, ts, redirectURI)
	query := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"state": {"client-error-state"}, "code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"},
		"resource": {ts.URL + "/mcp/"}, "scope": {"mcp"},
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authorize, err := client.Get(ts.URL + "/__tyk-as/test/authorize?" + query.Encode())
	require.NoError(t, err)
	_ = authorize.Body.Close()
	location, err := authorize.Location()
	require.NoError(t, err)
	callback := ts.URL + "/__tyk-as/test/callback?" + url.Values{
		"state": {location.Query().Get("state")}, "error": {"access_denied"}, "iss": {upstream.URL},
	}.Encode()
	response, err := client.Get(callback)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusFound, response.StatusCode)
	downstream, err := response.Location()
	require.NoError(t, err)
	require.Equal(t, "access_denied", downstream.Query().Get("error"))
	require.Equal(t, "client-error-state", downstream.Query().Get("state"))
	require.Equal(t, ts.URL+"/__tyk-as/test", downstream.Query().Get("iss"))
	require.Empty(t, downstream.Query().Get("code"))
	capture.mu.Lock()
	require.Zero(t, capture.tokenRequests)
	capture.mu.Unlock()
	require.Nil(t, analyticsRecord.Load(), "broker callback routes must not create API analytics records")
	logBytes, err := json.Marshal(hook.AllEntries())
	require.NoError(t, err)
	require.NotContains(t, string(logBytes), "client-error-state")
	require.NotContains(t, string(logBytes), clientID)
}

func TestMCPOAuthBrokerCallbackRequiresAdvertisedIssuerAndRejectsHybrid(t *testing.T) {
	for name, callbackValues := range map[string]url.Values{
		"missing issuer": {"code": {"upstream-code"}},
		"hybrid":         {"code": {"upstream-code"}, "error": {"access_denied"}},
	} {
		t.Run(name, func(t *testing.T) {
			ts, upstream, capture := newMCPBrokerTest(t, "/mcp/")
			clientID := registerMCPBrokerClient(t, ts, "https://client.example/callback")
			query := url.Values{
				"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://client.example/callback"},
				"state": {"client-state"}, "code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"},
				"resource": {ts.URL + "/mcp/"}, "scope": {"mcp"},
			}
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			authorize, err := client.Get(ts.URL + "/__tyk-as/test/authorize?" + query.Encode())
			require.NoError(t, err)
			_ = authorize.Body.Close()
			location, err := authorize.Location()
			require.NoError(t, err)
			values := cloneURLValues(callbackValues)
			values.Set("state", location.Query().Get("state"))
			if name == "hybrid" {
				values.Set("iss", upstream.URL)
			}
			response, err := client.Get(ts.URL + "/__tyk-as/test/callback?" + values.Encode())
			require.NoError(t, err)
			_ = response.Body.Close()
			require.Equal(t, http.StatusBadRequest, response.StatusCode)
			capture.mu.Lock()
			require.Zero(t, capture.tokenRequests)
			capture.mu.Unlock()
		})
	}
}

func TestMCPOAuthBrokerTokenRejectsWrongVerifierAndIsolation(t *testing.T) {
	ts, _, capture := newMCPBrokerTest(t, "/mcp/")
	logger, hook := logrustest.NewNullLogger()
	originalLog := log
	log = logger
	t.Cleanup(func() { log = originalLog })
	analyticsRecord := captureAnalytics(ts)
	redirectURI := "https://client.example/callback"
	clientID, correctVerifier, code := runMCPBrokerAuthorization(t, ts, redirectURI, "client-state")
	wrongVerifier := strings.Repeat("x", 43)
	wrong := exchangeMCPBrokerToken(t, ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirectURI}, "code_verifier": {wrongVerifier}, "resource": {ts.URL + "/mcp/"},
	}, http.StatusBadRequest)
	require.Empty(t, wrong.AccessToken)
	capture.mu.Lock()
	require.Equal(t, 1, capture.tokenRequests, "only the callback may contact the upstream token endpoint")
	capture.mu.Unlock()
	require.Nil(t, analyticsRecord.Load(), "broker token routes must not create API analytics records")
	logBytes, err := json.Marshal(hook.AllEntries())
	require.NoError(t, err)
	for _, secret := range []string{clientID, code, correctVerifier, wrongVerifier, "upstream-access-1", "upstream-refresh-2"} {
		require.NotContains(t, string(logBytes), secret)
	}

	clientID, verifier, code := runMCPBrokerAuthorization(t, ts, redirectURI, "second-state")
	tokens := exchangeMCPBrokerToken(t, ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}, "resource": {ts.URL + "/mcp/"},
	}, http.StatusOK)
	spec := ts.Gw.getApiSpec("test")
	foreign := &APISpec{APIDefinition: &apidef.APIDefinition{
		APIID: "other-api", OrgID: spec.OrgID, MCP: spec.MCP,
	}}
	middleware := &MCPOAuthBrokerTokenMiddleware{BaseMiddleware: &BaseMiddleware{Gw: ts.Gw, Spec: foreign}}
	request := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	err, status := middleware.ProcessRequest(httptest.NewRecorder(), request, nil)
	require.Error(t, err)
	require.Equal(t, http.StatusUnauthorized, status)

	foreign = &APISpec{APIDefinition: &apidef.APIDefinition{
		APIID: spec.APIID, OrgID: "other-org", MCP: spec.MCP,
	}}
	middleware.Spec = foreign
	err, status = middleware.ProcessRequest(httptest.NewRecorder(), request, nil)
	require.Error(t, err)
	require.Equal(t, http.StatusUnauthorized, status)
}

func TestMCPOAuthBrokerRecordsAreSealedAndBoundToKey(t *testing.T) {
	ts, _, _ := newMCPBrokerTest(t, "/mcp/")
	broker := newMCPOAuthBroker(ts.Gw, ts.Gw.getApiSpec("test"))
	record := mcpOAuthTokenGrant{OrgID: "default", APIID: "test", UpstreamAccessToken: "upstream-secret-token"}
	first, err := broker.sealRecord("record-one", record)
	require.NoError(t, err)
	second, err := broker.sealRecord("record-one", record)
	require.NoError(t, err)
	require.NotEqual(t, first, second, "each record must use a fresh nonce")
	require.NotContains(t, string(first), "upstream-secret-token")
	var opened mcpOAuthTokenGrant
	require.NoError(t, broker.openRecord("record-one", first, &opened))
	require.Equal(t, record.UpstreamAccessToken, opened.UpstreamAccessToken)
	require.Error(t, broker.openRecord("record-two", first, &opened), "record-key AAD must prevent swapping ciphertext")
	first[len(first)-1] ^= 1
	require.Error(t, broker.openRecord("record-one", first, &opened), "tampering must fail authentication")
}

func TestMCPOAuthBrokerConcurrentRefreshReplayRevokesFamily(t *testing.T) {
	ts, _, _ := newMCPBrokerTest(t, "/mcp/")
	redirectURI := "https://client.example/callback"
	clientID, verifier, code := runMCPBrokerAuthorization(t, ts, redirectURI, "concurrent-state")
	tokens := exchangeMCPBrokerToken(t, ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}, "resource": {ts.URL + "/mcp/"},
	}, http.StatusOK)

	type refreshResult struct {
		status int
		tokens mcpBrokerTokens
		err    error
	}
	results := make(chan refreshResult, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			form := url.Values{
				"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
				"client_id": {clientID}, "resource": {ts.URL + "/mcp/"},
			}
			request, err := http.NewRequest(http.MethodPost, ts.URL+"/__tyk-as/test/token", strings.NewReader(form.Encode()))
			if err != nil {
				results <- refreshResult{err: err}
				return
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				results <- refreshResult{err: err}
				return
			}
			defer response.Body.Close()
			result := refreshResult{status: response.StatusCode}
			if response.StatusCode == http.StatusOK {
				result.err = json.NewDecoder(response.Body).Decode(&result.tokens)
			}
			results <- result
		}()
	}
	close(start)
	statuses := map[int]int{}
	var rotated mcpBrokerTokens
	for range 2 {
		result := <-results
		require.NoError(t, result.err)
		statuses[result.status]++
		if result.status == http.StatusOK {
			rotated = result.tokens
		}
	}
	require.LessOrEqual(t, statuses[http.StatusOK], 1)
	require.GreaterOrEqual(t, statuses[http.StatusBadRequest], 1)
	require.Equal(t, 2, statuses[http.StatusOK]+statuses[http.StatusBadRequest])

	spec := ts.Gw.getApiSpec("test")
	middleware := &MCPOAuthBrokerTokenMiddleware{BaseMiddleware: &BaseMiddleware{Gw: ts.Gw, Spec: spec}}
	accessTokens := []string{tokens.AccessToken}
	if rotated.AccessToken != "" {
		accessTokens = append(accessTokens, rotated.AccessToken)
	}
	for _, accessToken := range accessTokens {
		request := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
		request.Header.Set("Authorization", "Bearer "+accessToken)
		err, status := middleware.ProcessRequest(httptest.NewRecorder(), request, nil)
		require.Error(t, err)
		require.Equal(t, http.StatusUnauthorized, status)
	}
}
