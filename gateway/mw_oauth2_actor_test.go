package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

// capturedExchange records the actor fields of the last exchange form the IdP saw.
type capturedExchange struct {
	mu             sync.Mutex
	calls          int32
	actorToken     string
	actorTokenType string
}

func (c *capturedExchange) snapshot() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.actorToken, c.actorTokenType
}

// actorCapturingIdP mints an exchanged token and records the actor_token /
// actor_token_type form fields the exchange request carried.
func actorCapturingIdP(t *testing.T) (*httptest.Server, *capturedExchange) {
	t.Helper()
	cap := &capturedExchange{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		cap.mu.Lock()
		atomic.AddInt32(&cap.calls, 1)
		cap.actorToken = r.PostForm.Get(oas.OAuth2FormActorToken)
		cap.actorTokenType = r.PostForm.Get(oas.OAuth2FormActorTokenType)
		cap.mu.Unlock()

		header64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		payload64 := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://exchanged-idp","sub":"alice"}`))
		w.Header().Set(header.ContentType, header.ApplicationJSON)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": header64 + "." + payload64 + ".sig",
			"expires_in":   300,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

// headerCapturingUpstream records every request header so a test can assert
// the actor-token header was (or wasn't) forwarded upstream.
type headerCapturingUpstream struct {
	mu      sync.Mutex
	headers http.Header
}

func (u *headerCapturingUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.headers = r.Header.Clone()
	u.mu.Unlock()
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (u *headerCapturingUpstream) get(key string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.headers.Get(key)
}

// mintInboundJWTWithMayAct returns an unsigned inbound JWT carrying a may_act
// claim naming the given actor sub.
func mintInboundJWTWithMayAct(t *testing.T, iss, mayActSub string) string {
	t.Helper()
	payload := map[string]interface{}{
		"iss": iss, "sub": "alice", "azp": "mcp-client",
		"may_act": map[string]string{"sub": mayActSub},
	}
	pj, _ := json.Marshal(payload)
	header64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	return header64 + "." + base64.RawURLEncoding.EncodeToString(pj) + ".sig"
}

// buildActorExchangeAPI is buildOAuth2ExchangeAPI with an actorToken block
// injected into the provider.
func buildActorExchangeAPI(idpIss, idpEndpoint, listenPath, actorBlockJSON string) string {
	return fmt.Sprintf(`{
		"openapi": "3.0.3",
		"info": {"title": "story07", "version": "1.0.0"},
		"paths": {"/mail": {"get": {"operationId": "getMail", "responses": {"200": {"description": "ok"}}}}},
		"components": {"securitySchemes": {"corpOAuth": {"type": "oauth2", "flows": {"authorizationCode": {"authorizationUrl": "x", "tokenUrl": "x", "scopes": {}}}}}},
		"security": [{"corpOAuth": []}],
		"x-tyk-api-gateway": {
			"info": {"name": "story07"},
			"server": {
				"listenPath": {"value": %q, "strip": true},
				"authentication": {
					"enabled": true,
					"securitySchemes": {
						"corpOAuth": {
							"enabled": true,
							"tokenExchange": {
								"enabled": true,
								"providers": [{
									"name": "primary",
									"issuers": [%q],
									"tokenEndpoint": %q,
									"clientAuth": {"method": "client_secret_basic", "clientId": "tyk-gateway", "clientSecret": "shh"},
									"defaultTarget": {"audience": "upstream-api"},
									"actorToken": %s
								}]
							}
						}
					}
				}
			},
			"middleware": {"operations": {"getMail": {"exchange": {"enabled": true, "scopes": ["users:read"]}}}}
		}
	}`, listenPath, idpIss, idpEndpoint, actorBlockJSON)
}

func loadActorAPI(t *testing.T, ts *Test, oasJSON, listenPath, targetURL string) {
	t.Helper()
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.IsOAS = true
		require.NoError(t, spec.OAS.UnmarshalJSON([]byte(oasJSON)))
		spec.OAS.ExtractTo(spec.APIDefinition)
		spec.APIID = "story07-actor"
		spec.Proxy.ListenPath = listenPath
		spec.Proxy.TargetURL = targetURL
		spec.Proxy.StripListenPath = true
		spec.Name = "story07-actor"
		spec.UseKeylessAccess = true
	})
}

// TestOAuth2Actor_HeaderSource_SendsActorTokenAndStrips pins TC2: the header
// actor token is sent to the IdP as actor_token (+ access_token type) and
// stripped from the upstream request.
func TestOAuth2Actor_HeaderSource_SendsActorTokenAndStrips(t *testing.T) {
	if !oauth2BuildIsEE {
		t.Skip("actor token is EE-only")
	}
	idp, cap := actorCapturingIdP(t)
	upstream := &headerCapturingUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	t.Cleanup(upstreamSrv.Close)

	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	const listenPath = "/story07/"
	oasJSON := buildActorExchangeAPI(idp.URL, idp.URL+"/token", listenPath, `{"source": "header"}`)
	loadActorAPI(t, ts, oasJSON, listenPath, upstreamSrv.URL)

	inbound := mintInboundUnverifiedJWT(t, idp.URL)
	resp, err := ts.Run(t, test.TestCase{
		Path:   "/story07/mail",
		Method: http.MethodGet,
		Headers: map[string]string{
			header.Authorization: oas.OAuth2AuthSchemeBearer + " " + inbound,
			"X-Actor-Token":      "header-actor-token",
		},
		Code: http.StatusOK,
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	gotActor, gotType := cap.snapshot()
	assert.Equal(t, "header-actor-token", gotActor, "the header actor token must be sent as actor_token")
	assert.Equal(t, oas.OAuth2TokenTypeAccessToken, gotType, "actor_token_type defaults to access_token")
	assert.Empty(t, upstream.get("X-Actor-Token"), "the actor header must be stripped from the upstream request")
}

// TestOAuth2Actor_HeaderRequiredMissing_401 pins TC4: a missing required actor
// header is rejected with a 401 RFC 6750 invalid_token challenge, and the IdP
// is never called.
func TestOAuth2Actor_HeaderRequiredMissing_401(t *testing.T) {
	if !oauth2BuildIsEE {
		t.Skip("actor token is EE-only")
	}
	idp, cap := actorCapturingIdP(t)
	upstream := &headerCapturingUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	t.Cleanup(upstreamSrv.Close)

	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	const listenPath = "/story07/"
	oasJSON := buildActorExchangeAPI(idp.URL, idp.URL+"/token", listenPath, `{"source": "header"}`)
	loadActorAPI(t, ts, oasJSON, listenPath, upstreamSrv.URL)

	inbound := mintInboundUnverifiedJWT(t, idp.URL)
	resp, err := ts.Run(t, test.TestCase{
		Path:    "/story07/mail",
		Method:  http.MethodGet,
		Headers: map[string]string{header.Authorization: oas.OAuth2AuthSchemeBearer + " " + inbound},
		Code:    http.StatusUnauthorized,
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	assert.Contains(t, resp.Header.Get(header.WWWAuthenticate), `error="invalid_token"`)
	assert.Contains(t, string(body), "invalid_token")
	assert.Equal(t, int32(0), atomic.LoadInt32(&cap.calls), "the exchange IdP must not be called when the required actor header is absent")
}

// TestOAuth2Actor_RequireMayAct_Mismatch_403 pins TC19/TC20: a subject token
// whose may_act does not authorize the configured actor is rejected with 403
// actor_not_authorized before any IdP call — including the actor-CC endpoint.
func TestOAuth2Actor_RequireMayAct_Mismatch_403(t *testing.T) {
	if !oauth2BuildIsEE {
		t.Skip("actor token is EE-only")
	}
	idp, cap := actorCapturingIdP(t)
	upstream := &headerCapturingUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	t.Cleanup(upstreamSrv.Close)

	var actorCCCalls int32
	actorCC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&actorCCCalls, 1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "cc-actor", "expires_in": 3600})
	}))
	t.Cleanup(actorCC.Close)

	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	const listenPath = "/story07/"
	actorBlock := fmt.Sprintf(`{"source": "client_credentials", "requireMayAct": true, "clientCredentials": {"tokenEndpoint": %q, "clientId": "tyk-gateway-actor"}}`, actorCC.URL)
	oasJSON := buildActorExchangeAPI(idp.URL, idp.URL+"/token", listenPath, actorBlock)
	loadActorAPI(t, ts, oasJSON, listenPath, upstreamSrv.URL)

	inbound := mintInboundJWTWithMayAct(t, idp.URL, "some-other-actor")
	resp, err := ts.Run(t, test.TestCase{
		Path:    "/story07/mail",
		Method:  http.MethodGet,
		Headers: map[string]string{header.Authorization: oas.OAuth2AuthSchemeBearer + " " + inbound},
		Code:    http.StatusForbidden,
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	assert.Contains(t, string(body), oas.OAuth2ErrActorNotAuthorized)
	assert.Equal(t, int32(0), atomic.LoadInt32(&cap.calls), "the exchange IdP must not be called on a may_act rejection")
	assert.Equal(t, int32(0), atomic.LoadInt32(&actorCCCalls), "the actor-CC endpoint must not be called on a may_act rejection")
}
