package upstreamoauth_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/TykTechnologies/tyk/ee/middleware/upstreamoauth"
	"github.com/TykTechnologies/tyk/gateway"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

var StartTest = gateway.StartTest

type APISpec = gateway.APISpec

const ClientCredentialsAuthorizeType = upstreamoauth.ClientCredentialsAuthorizeType
const PasswordAuthorizeType = upstreamoauth.PasswordAuthorizeType

func TestProvider_ClientCredentialsAuthorizeType(t *testing.T) {
	tst := StartTest(nil)
	t.Cleanup(tst.Close)

	var requestCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if requestCount > 0 {
			assert.Fail(t, "Unexpected request received.")
		}
		requestCount++
		if r.URL.String() != "/token" {
			assert.Fail(t, "authenticate client request URL = %q; want %q", r.URL, "/token")
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			assert.Fail(t, "Unexpected authorization header, %v is found.", headerAuth)
		}
		if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
			assert.Fail(t, "Content-Type header = %q; want %q", got, want)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			r.Body.Close()
		}
		if err != nil {
			assert.Fail(t, "failed reading request body: %s.", err)
		}
		if string(body) != "grant_type=client_credentials&scope=scope1+scope2" {
			assert.Fail(t, "payload = %q; want %q", string(body), "grant_type=client_credentials&scope=scope1+scope2")
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&token_type=bearer&instance_url=https://tykxample.com"))
	}))
	defer t.Cleanup(func() { ts.Close() })

	cfg := apidef.ClientCredentials{
		ClientAuthData: apidef.ClientAuthData{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
		},
		TokenURL:      ts.URL + "/token",
		Scopes:        []string{"scope1", "scope2"},
		Header:        apidef.AuthSource{Enabled: true, Name: "Authorization"},
		ExtraMetadata: []string{"instance_url"},
	}

	tst.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/upstream-oauth-distributed/"
			spec.UseKeylessAccess = true
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled: true,
				OAuth: apidef.UpstreamOAuth{
					Enabled:               true,
					ClientCredentials:     cfg,
					AllowedAuthorizeTypes: []string{apidef.OAuthAuthorizationTypeClientCredentials},
				},
			}
			spec.Proxy.StripListenPath = true
		},
	)

	_, _ = tst.Run(t, test.TestCases{
		{
			Path: "/upstream-oauth-distributed/",
			Code: http.StatusOK,
			BodyMatchFunc: func(body []byte) bool {
				resp := struct {
					Headers map[string]string `json:"headers"`
				}{}
				err := json.Unmarshal(body, &resp)
				assert.NoError(t, err)

				assert.Contains(t, resp.Headers, header.Authorization)
				assert.NotEmpty(t, resp.Headers[header.Authorization])
				assert.Equal(t, "Bearer 90d64460d14870c08c81352a05dedd3465940a7c", resp.Headers[header.Authorization])

				return true
			},
		},
		{
			Path: "/upstream-oauth-distributed/",
			Code: http.StatusOK,
			BodyMatchFunc: func(body []byte) bool {
				resp := struct {
					Headers map[string]string `json:"headers"`
				}{}
				err := json.Unmarshal(body, &resp)
				assert.NoError(t, err)

				assert.Contains(t, resp.Headers, header.Authorization)
				assert.NotEmpty(t, resp.Headers[header.Authorization])
				assert.Equal(t, "Bearer 90d64460d14870c08c81352a05dedd3465940a7c", resp.Headers[header.Authorization])

				return true
			},
		},
	}...)

}

func TestProvider_PasswordAuthorizeType(t *testing.T) {
	tst := StartTest(nil)
	t.Cleanup(tst.Close)

	var requestCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if requestCount > 0 {
			assert.Fail(t, "Unexpected request received.")
		}
		requestCount++
		expected := "/token"
		if r.URL.String() != expected {
			assert.Fail(t, "URL = %q; want %q", r.URL, expected)
		}
		headerAuth := r.Header.Get("Authorization")
		expected = "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ="
		if headerAuth != expected {
			assert.Fail(t, "Authorization header = %q; want %q", headerAuth, expected)
		}
		headerContentType := r.Header.Get("Content-Type")
		expected = "application/x-www-form-urlencoded"
		if headerContentType != expected {
			assert.Fail(t, "Content-Type header = %q; want %q", headerContentType, expected)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			assert.Fail(t, "Failed reading request body: %s.", err)
		}
		expected = "grant_type=password&password=password1&scope=scope1+scope2&username=user1"
		if string(body) != expected {
			assert.Fail(t, "payload = %q; want %q", string(body), expected)
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer&instance_url=https://tykxample.com"))
	}))
	defer t.Cleanup(func() { ts.Close() })

	cfg := apidef.PasswordAuthentication{
		ClientAuthData: apidef.ClientAuthData{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
		},
		Username:      "user1",
		Password:      "password1",
		TokenURL:      ts.URL + "/token",
		Scopes:        []string{"scope1", "scope2"},
		Header:        apidef.AuthSource{Enabled: true, Name: "Authorization"},
		ExtraMetadata: []string{"instance_url"},
	}

	tst.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/upstream-oauth-password/"
			spec.UseKeylessAccess = true
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled: true,
				OAuth: apidef.UpstreamOAuth{
					Enabled:                true,
					PasswordAuthentication: cfg,
					AllowedAuthorizeTypes:  []string{apidef.OAuthAuthorizationTypePassword},
				},
			}
			spec.Proxy.StripListenPath = true
		},
	)

	_, _ = tst.Run(t, test.TestCases{
		{
			Path: "/upstream-oauth-password/",
			Code: http.StatusOK,
			BodyMatchFunc: func(body []byte) bool {
				resp := struct {
					Headers map[string]string `json:"headers"`
				}{}
				err := json.Unmarshal(body, &resp)
				assert.NoError(t, err)

				assert.Contains(t, resp.Headers, header.Authorization)
				assert.NotEmpty(t, resp.Headers[header.Authorization])
				assert.Equal(t, "Bearer 90d64460d14870c08c81352a05dedd3465940a7c", resp.Headers[header.Authorization])

				return true
			},
		},
		{
			Path: "/upstream-oauth-password/",
			Code: http.StatusOK,
			BodyMatchFunc: func(body []byte) bool {
				resp := struct {
					Headers map[string]string `json:"headers"`
				}{}
				err := json.Unmarshal(body, &resp)
				assert.NoError(t, err)

				assert.Contains(t, resp.Headers, header.Authorization)
				assert.NotEmpty(t, resp.Headers[header.Authorization])
				assert.Equal(t, "Bearer 90d64460d14870c08c81352a05dedd3465940a7c", resp.Headers[header.Authorization])

				return true
			},
		},
	}...)
}

// bodyOnlyTokenServer imitates an IdP that rejects header (Basic) client
// authentication and only accepts client credentials in the request body.
// Every token request increments *requestCount; expectedForm keys are asserted
// against the successful (body-credentials) request.
func bodyOnlyTokenServer(t *testing.T, requestCount *int, expectedForm url.Values) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		*requestCount++

		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		parsed, err := url.ParseQuery(string(body))
		assert.NoError(t, err)
		for key, want := range expectedForm {
			assert.Equal(t, want, parsed[key], "form key %q", key)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"body-only-token","token_type":"bearer","expires_in":3600}`))
	}))
}

// headerOnlyTokenServer imitates an IdP that only accepts client credentials
// via HTTP Basic authentication and rejects credentials in the request body.
func headerOnlyTokenServer(t *testing.T, requestCount *int, wantBasicAuth string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		*requestCount++

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		parsed, err := url.ParseQuery(string(body))
		assert.NoError(t, err)

		if r.Header.Get("Authorization") != wantBasicAuth || parsed.Get("client_secret") != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"header-only-token","token_type":"bearer","expires_in":3600}`))
	}))
}

// buildUpstreamOAuthAPI loads a keyless API proxying with the given upstream
// OAuth configuration on the given listen path.
func buildUpstreamOAuthAPI(tst *gateway.Test, listenPath string, oauth apidef.UpstreamOAuth) {
	tst.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Proxy.ListenPath = listenPath
			spec.UseKeylessAccess = true
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled: true,
				OAuth:   oauth,
			}
			spec.Proxy.StripListenPath = true
		},
	)
}

func TestProvider_ClientCredentials_MethodPost(t *testing.T) {
	tst := StartTest(nil)
	t.Cleanup(tst.Close)

	var requestCount int
	ts := bodyOnlyTokenServer(t, &requestCount, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"CC_POST_CLIENT"},
		"client_secret": {"CC_POST_SECRET"},
	})
	t.Cleanup(ts.Close)

	buildUpstreamOAuthAPI(tst, "/upstream-oauth-cc-post/", apidef.UpstreamOAuth{
		Enabled:               true,
		AllowedAuthorizeTypes: []string{apidef.OAuthAuthorizationTypeClientCredentials},
		ClientCredentials: apidef.ClientCredentials{
			ClientAuthData: apidef.ClientAuthData{
				ClientID:     "CC_POST_CLIENT",
				ClientSecret: "CC_POST_SECRET",
				Method:       apidef.OAuth2ClientAuthPost,
			},
			TokenURL: ts.URL + "/token",
			Header:   apidef.AuthSource{Enabled: true, Name: "Authorization"},
		},
	})

	_, _ = tst.Run(t, test.TestCase{
		Path: "/upstream-oauth-cc-post/",
		Code: http.StatusOK,
		BodyMatchFunc: func(body []byte) bool {
			resp := struct {
				Headers map[string]string `json:"headers"`
			}{}
			assert.NoError(t, json.Unmarshal(body, &resp))
			assert.Equal(t, "Bearer body-only-token", resp.Headers[header.Authorization])
			return true
		},
	})

	assert.Equal(t, 1, requestCount, "expected a single token request with body credentials, no Basic Auth probe")
}

func TestProvider_Password_MethodPost(t *testing.T) {
	tst := StartTest(nil)
	t.Cleanup(tst.Close)

	// The password-grant token cache key is derived from client ID, secret and
	// scopes only (not the token URL), so use per-run credentials to avoid
	// serving a token cached in Redis by a previous run.
	clientID := fmt.Sprintf("PW_POST_CLIENT_%d", time.Now().UnixNano())

	var requestCount int
	ts := bodyOnlyTokenServer(t, &requestCount, url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientID},
		"client_secret": {"PW_POST_SECRET"},
		"username":      {"user1"},
		"password":      {"password1"},
	})
	t.Cleanup(ts.Close)

	buildUpstreamOAuthAPI(tst, "/upstream-oauth-pw-post/", apidef.UpstreamOAuth{
		Enabled:               true,
		AllowedAuthorizeTypes: []string{apidef.OAuthAuthorizationTypePassword},
		PasswordAuthentication: apidef.PasswordAuthentication{
			ClientAuthData: apidef.ClientAuthData{
				ClientID:     clientID,
				ClientSecret: "PW_POST_SECRET",
				Method:       apidef.OAuth2ClientAuthPost,
			},
			Username: "user1",
			Password: "password1",
			TokenURL: ts.URL + "/token",
			Header:   apidef.AuthSource{Enabled: true, Name: "Authorization"},
		},
	})

	_, _ = tst.Run(t, test.TestCase{
		Path: "/upstream-oauth-pw-post/",
		Code: http.StatusOK,
		BodyMatchFunc: func(body []byte) bool {
			resp := struct {
				Headers map[string]string `json:"headers"`
			}{}
			assert.NoError(t, json.Unmarshal(body, &resp))
			assert.Equal(t, "Bearer body-only-token", resp.Headers[header.Authorization])
			return true
		},
	})

	assert.Equal(t, 1, requestCount, "expected a single token request with body credentials, no Basic Auth probe")
}

func TestProvider_ClientCredentials_MethodBasic(t *testing.T) {
	tst := StartTest(nil)
	t.Cleanup(tst.Close)

	var requestCount int
	ts := headerOnlyTokenServer(t, &requestCount, "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=")
	t.Cleanup(ts.Close)

	buildUpstreamOAuthAPI(tst, "/upstream-oauth-cc-basic/", apidef.UpstreamOAuth{
		Enabled:               true,
		AllowedAuthorizeTypes: []string{apidef.OAuthAuthorizationTypeClientCredentials},
		ClientCredentials: apidef.ClientCredentials{
			ClientAuthData: apidef.ClientAuthData{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				Method:       apidef.OAuth2ClientAuthBasic,
			},
			TokenURL: ts.URL + "/token",
			Header:   apidef.AuthSource{Enabled: true, Name: "Authorization"},
		},
	})

	_, _ = tst.Run(t, test.TestCase{
		Path: "/upstream-oauth-cc-basic/",
		Code: http.StatusOK,
		BodyMatchFunc: func(body []byte) bool {
			resp := struct {
				Headers map[string]string `json:"headers"`
			}{}
			assert.NoError(t, json.Unmarshal(body, &resp))
			assert.Equal(t, "Bearer header-only-token", resp.Headers[header.Authorization])
			return true
		},
	})

	assert.Equal(t, 1, requestCount, "expected a single token request with header credentials")
}

// TestProvider_ClientCredentials_MethodEmpty_AutoDetectFallback pins the
// backwards-compatible default: with method unset, Tyk keeps the RFC
// auto-detect behaviour — the first attempt uses Basic Auth (rejected by a
// body-only IdP), the second retries with body credentials and succeeds.
func TestProvider_ClientCredentials_MethodEmpty_AutoDetectFallback(t *testing.T) {
	tst := StartTest(nil)
	t.Cleanup(tst.Close)

	var requestCount int
	ts := bodyOnlyTokenServer(t, &requestCount, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"CC_AUTO_CLIENT"},
		"client_secret": {"CC_AUTO_SECRET"},
	})
	t.Cleanup(ts.Close)

	buildUpstreamOAuthAPI(tst, "/upstream-oauth-cc-auto/", apidef.UpstreamOAuth{
		Enabled:               true,
		AllowedAuthorizeTypes: []string{apidef.OAuthAuthorizationTypeClientCredentials},
		ClientCredentials: apidef.ClientCredentials{
			ClientAuthData: apidef.ClientAuthData{
				ClientID:     "CC_AUTO_CLIENT",
				ClientSecret: "CC_AUTO_SECRET",
			},
			TokenURL: ts.URL + "/token",
			Header:   apidef.AuthSource{Enabled: true, Name: "Authorization"},
		},
	})

	_, _ = tst.Run(t, test.TestCase{
		Path: "/upstream-oauth-cc-auto/",
		Code: http.StatusOK,
		BodyMatchFunc: func(body []byte) bool {
			resp := struct {
				Headers map[string]string `json:"headers"`
			}{}
			assert.NoError(t, json.Unmarshal(body, &resp))
			assert.Equal(t, "Bearer body-only-token", resp.Headers[header.Authorization])
			return true
		},
	})

	assert.Equal(t, 2, requestCount, "expected the auto-detect probe: failed Basic Auth attempt followed by a body-credentials retry")
}

// TestProvider_ClientCredentials_MethodPost_NoFallbackOnMismatch verifies an
// explicit method is honoured: body-only credentials against a header-only
// IdP fail without a silent fallback to Basic Auth.
func TestProvider_ClientCredentials_MethodPost_NoFallbackOnMismatch(t *testing.T) {
	tst := StartTest(nil)
	t.Cleanup(tst.Close)

	var requestCount int
	ts := headerOnlyTokenServer(t, &requestCount, "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=")
	t.Cleanup(ts.Close)

	buildUpstreamOAuthAPI(tst, "/upstream-oauth-cc-mismatch/", apidef.UpstreamOAuth{
		Enabled:               true,
		AllowedAuthorizeTypes: []string{apidef.OAuthAuthorizationTypeClientCredentials},
		ClientCredentials: apidef.ClientCredentials{
			ClientAuthData: apidef.ClientAuthData{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				Method:       apidef.OAuth2ClientAuthPost,
			},
			TokenURL: ts.URL + "/token",
			Header:   apidef.AuthSource{Enabled: true, Name: "Authorization"},
		},
	})

	_, _ = tst.Run(t, test.TestCase{
		Path: "/upstream-oauth-cc-mismatch/",
		Code: http.StatusInternalServerError,
	})

	assert.Equal(t, 1, requestCount, "expected a single rejected token request and no fallback to header credentials")
}

func TestSetExtraMetadata(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://tykxample.com", nil)

	keyList := []string{"key1", "key2"}
	token := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	upstreamoauth.SetExtraMetadata(req, keyList, token)

	contextData := upstreamoauth.CtxGetData(req)

	assert.Equal(t, "value1", contextData["key1"])
	assert.Equal(t, "value2", contextData["key2"])
	assert.NotContains(t, contextData, "key3")
}

func TestBuildMetadataMap(t *testing.T) {
	token := &oauth2.Token{
		AccessToken: "tyk_upstream_oauth_access_token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	token = token.WithExtra(map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": "",
	})
	extraMetadataKeys := []string{"key1", "key2", "key3", "key4"}

	metadataMap := upstreamoauth.BuildMetadataMap(token, extraMetadataKeys)

	assert.Equal(t, "value1", metadataMap["key1"])
	assert.Equal(t, "value2", metadataMap["key2"])
	assert.NotContains(t, metadataMap, "key3")
	assert.NotContains(t, metadataMap, "key4")
}

func TestCreateTokenDataBytes(t *testing.T) {
	token := &oauth2.Token{
		AccessToken: "tyk_upstream_oauth_access_token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	token = token.WithExtra(map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": "",
	})

	extraMetadataKeys := []string{"key1", "key2", "key3", "key4"}

	encryptedToken := "encrypted_tyk_upstream_oauth_access_token"
	tokenDataBytes, err := upstreamoauth.CreateTokenDataBytes(encryptedToken, token, extraMetadataKeys)

	assert.NoError(t, err)

	var tokenData upstreamoauth.TokenData
	err = json.Unmarshal(tokenDataBytes, &tokenData)
	assert.NoError(t, err)

	assert.Equal(t, encryptedToken, tokenData.Token)
	assert.Equal(t, "value1", tokenData.ExtraMetadata["key1"])
	assert.Equal(t, "value2", tokenData.ExtraMetadata["key2"])
	assert.NotContains(t, tokenData.ExtraMetadata, "key3")
	assert.NotContains(t, tokenData.ExtraMetadata, "key4")
}

func TestUnmarshalTokenData(t *testing.T) {
	tokenData := upstreamoauth.TokenData{
		Token: "tyk_upstream_oauth_access_token",
		ExtraMetadata: map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
		},
	}

	tokenDataBytes, err := json.Marshal(tokenData)
	assert.NoError(t, err)

	result, err := upstreamoauth.UnmarshalTokenData(string(tokenDataBytes))

	assert.NoError(t, err)

	assert.Equal(t, tokenData.Token, result.Token)
	assert.Equal(t, tokenData.ExtraMetadata, result.ExtraMetadata)
}
