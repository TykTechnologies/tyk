package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

func TestUpstreamOauth2(t *testing.T) {

	tst := StartTest(nil)
	t.Cleanup(tst.Close)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&token_type=bearer"))
	}))
	defer t.Cleanup(func() { ts.Close() })

	cfg := apidef.ClientCredentials{
		Enabled: true,
		ClientAuthData: apidef.ClientAuthData{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
		},
		TokenURL: ts.URL + "/token",
		Scopes:   []string{"scope1", "scope2"},
	}

	tst.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/upstream-oauth-distributed/"
			spec.UseKeylessAccess = true
			spec.UpstreamAuth = apidef.UpstreamAuth{
				Enabled: true,
				OAuth: apidef.UpstreamOAuth{
					Enabled:           true,
					ClientCredentials: cfg,
					HeaderName:        "",
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
	}...)

}

func TestPasswordCredentialsTokenRequest(t *testing.T) {
	tst := StartTest(nil)
	t.Cleanup(tst.Close)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
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
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
	}))
	defer t.Cleanup(func() { ts.Close() })

	cfg := apidef.PasswordAuthentication{
		Enabled: true,
		ClientAuthData: apidef.ClientAuthData{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
		},
		Username: "user1",
		Password: "password1",
		TokenURL: ts.URL + "/token",
		Scopes:   []string{"scope1", "scope2"},
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
					HeaderName:             "",
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
	}...)
}
