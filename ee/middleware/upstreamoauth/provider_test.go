package upstreamoauth_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
