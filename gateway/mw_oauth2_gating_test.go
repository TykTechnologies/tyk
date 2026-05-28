package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

// fakeIdP returns a test IdP that mints a deterministic base64url-encoded exchanged token.
func fakeIdP(t *testing.T, requireBasic bool) (*httptest.Server, *int32) {
	t.Helper()
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		if requireBasic {
			user, pass, ok := r.BasicAuth()
			if !ok || user == "" || pass == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		_ = r.ParseForm()
		aud := r.PostForm.Get(oas.OAuth2FormAudience)
		scope := r.PostForm.Get(oas.OAuth2FormScope)
		payload := map[string]interface{}{"aud": aud, "scope": scope, "iss": "https://exchanged-idp", "sub": "alice"}
		payloadJSON, _ := json.Marshal(payload)
		header64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		payload64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
		access := header64 + "." + payload64 + ".sig"
		w.Header().Set(header.ContentType, header.ApplicationJSON)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":      access,
			"issued_token_type": oas.OAuth2TokenTypeAccessToken,
			"token_type":        "Bearer",
			"expires_in":        300,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &callCount
}

// mintInboundUnverifiedJWT returns an unsigned JWT triple with iss and sub claims.
func mintInboundUnverifiedJWT(t *testing.T, iss string) string {
	t.Helper()
	payload := map[string]string{"iss": iss, "sub": "alice", "azp": "mcp-client"}
	pj, _ := json.Marshal(payload)
	header64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload64 := base64.RawURLEncoding.EncodeToString(pj)
	return header64 + "." + payload64 + ".sig"
}

// echoUpstream records the Authorization header it receives so the
// test can assert which token was forwarded.
type echoUpstream struct {
	authHeader atomic.Value // string
}

func (u *echoUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.authHeader.Store(r.Header.Get(header.Authorization))
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"headers": map[string]string{header.Authorization: r.Header.Get(header.Authorization)},
	})
}

func (u *echoUpstream) ReceivedBearer() string {
	v, _ := u.authHeader.Load().(string)
	return v
}

func buildOAuth2ExchangeAPI(idpIss, idpEndpoint string, listenPath string) string {
	return fmt.Sprintf(`{
		"openapi": "3.0.3",
		"info": {"title": "story06", "version": "1.0.0"},
		"paths": {
			"/mail": {"get": {"operationId": "getMail", "responses": {"200": {"description": "ok"}}}}
		},
		"components": {
			"securitySchemes": {
				"corpOAuth": {"type": "oauth2", "flows": {"authorizationCode": {"authorizationUrl": "x", "tokenUrl": "x", "scopes": {}}}}
			}
		},
		"security": [{"corpOAuth": []}],
		"x-tyk-api-gateway": {
			"info": {"name": "story06"},
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
									"defaultTarget": {"audience": "upstream-api"}
								}]
							}
						}
					}
				}
			},
			"middleware": {
				"operations": {
					"getMail": {"exchange": {"enabled": true, "scopes": ["users:read"]}}
				}
			}
		}
	}`, listenPath, idpIss, idpEndpoint)
}

func decodeExchangedToken(t *testing.T, bearer string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(bearer, ".")
	require.Len(t, parts, 3, "expected 3 JWT segments, got %d in %q", len(parts), bearer)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &m))
	return m
}

// TestOAuth2Gating_BuildFlavorParity verifies EE exchanges the token while OSS forwards it unchanged.
func TestOAuth2Gating_BuildFlavorParity(t *testing.T) {
	idp, idpCalls := fakeIdP(t, true)
	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	t.Cleanup(upstreamSrv.Close)

	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	const listenPath = "/story06/"
	oasJSON := buildOAuth2ExchangeAPI(idp.URL, idp.URL+"/token", listenPath)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.IsOAS = true
		require.NoError(t, spec.OAS.UnmarshalJSON([]byte(oasJSON)))
		spec.OAS.ExtractTo(spec.APIDefinition)
		spec.APIID = "story06-gating"
		spec.Proxy.ListenPath = listenPath
		spec.Proxy.TargetURL = upstreamSrv.URL
		spec.Proxy.StripListenPath = true
		spec.Name = "story06-gating"
		// Tyk's auth-method discovery treats the OAS oauth2 scheme as
		// "auth happens here" but the new-style block does not (yet)
		// introspect inbound tokens — leaving UseKeylessAccess off
		// would cause the auth chain to 403 the request before either
		// the scope-check or the exchange middleware runs.
		spec.UseKeylessAccess = true
	})

	inbound := mintInboundUnverifiedJWT(t, idp.URL)

	resp, err := ts.Run(t, test.TestCase{
		Path:    "/story06/mail",
		Method:  http.MethodGet,
		Headers: map[string]string{header.Authorization: oas.OAuth2AuthSchemeBearer + " " + inbound},
		Code:    http.StatusOK,
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	upstreamSawBearer := strings.TrimPrefix(upstream.ReceivedBearer(), oas.OAuth2AuthSchemeBearer+" ")
	upstreamSawBearer = strings.TrimSpace(upstreamSawBearer)

	if oauth2BuildIsEE {
		// EE: the IdP was called, the upstream saw the exchanged token.
		assert.Equal(t, int32(1), atomic.LoadInt32(idpCalls), "EE build should call the IdP")
		assert.NotEqual(t, inbound, upstreamSawBearer, "EE build should forward the exchanged token, not the inbound")
		claims := decodeExchangedToken(t, upstreamSawBearer)
		assert.Equal(t, "upstream-api", claims["aud"])
		assert.Equal(t, "users:read", claims["scope"])
	} else {
		// OSS: IdP not called; the upstream sees the inbound token unchanged.
		assert.Equal(t, int32(0), atomic.LoadInt32(idpCalls), "OSS build must not call the IdP")
		assert.Equal(t, inbound, upstreamSawBearer, "OSS build must forward the inbound token unchanged")
	}
}

// TestOAuth2Gating_NoMatchingProvider verifies EE returns 403 with a structured body when iss matches no provider.
func TestOAuth2Gating_NoMatchingProvider(t *testing.T) {
	idp, _ := fakeIdP(t, false)
	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	t.Cleanup(upstreamSrv.Close)

	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	const listenPath = "/story06-nomatch/"
	// Provider only accepts tokens issued by idp.URL; inbound token has
	// a different iss so the exchange runtime cannot find a match.
	oasJSON := buildOAuth2ExchangeAPI(idp.URL, idp.URL+"/token", listenPath)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.IsOAS = true
		require.NoError(t, spec.OAS.UnmarshalJSON([]byte(oasJSON)))
		spec.OAS.ExtractTo(spec.APIDefinition)
		spec.APIID = "story06-nomatch"
		spec.Proxy.ListenPath = listenPath
		spec.Proxy.TargetURL = upstreamSrv.URL
		spec.Proxy.StripListenPath = true
		spec.Name = "story06-nomatch"
		spec.UseKeylessAccess = true
	})

	wrongIss := "https://evil-idp.example.com"
	inbound := mintInboundUnverifiedJWT(t, wrongIss)

	resp, err := ts.Run(t, test.TestCase{
		Path:    "/story06-nomatch/mail",
		Method:  http.MethodGet,
		Headers: map[string]string{header.Authorization: oas.OAuth2AuthSchemeBearer + " " + inbound},
		// OSS noop passes through; EE returns 403.
		Code: func() int {
			if oauth2BuildIsEE {
				return http.StatusForbidden
			}
			return http.StatusOK
		}(),
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	if !oauth2BuildIsEE {
		return
	}

	// EE: verify the structured error body and WWW-Authenticate challenge.
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var errBody map[string]string
	require.NoError(t, json.Unmarshal(body, &errBody), "response must be valid JSON, got: %s", body)
	assert.Equal(t, oas.OAuth2ErrNoMatchingProvider, errBody["error"])
	assert.Equal(t, wrongIss, errBody["iss"], "iss echo in body lets MCP clients surface a meaningful step-up hint")
	assert.NotEmpty(t, errBody["error_description"])

	// Content-Type must be JSON (not a gateway-default HTML error).
	assert.Equal(t, header.ApplicationJSON, resp.Header.Get(header.ContentType))

	// WWW-Authenticate must carry the Bearer challenge with error params.
	wwwAuth := resp.Header.Get(header.WWWAuthenticate)
	assert.Contains(t, wwwAuth, oas.OAuth2AuthSchemeBearer)
	assert.Contains(t, wwwAuth, oas.OAuth2ErrNoMatchingProvider)

	// The upstream must NOT have been called — the exchange middleware
	// short-circuited before forwarding.
	assert.Empty(t, upstream.ReceivedBearer(), "upstream must not be reached on exchange error")
}
