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
			t.Errorf("authenticate client request URL = %q; want %q", r.URL, "/token")
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
		}
		if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
			t.Errorf("Content-Type header = %q; want %q", got, want)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			r.Body.Close()
		}
		if err != nil {
			t.Errorf("failed reading request body: %s.", err)
		}
		if string(body) != "grant_type=client_credentials&scope=scope1+scope2" {
			t.Errorf("payload = %q; want %q", string(body), "grant_type=client_credentials&scope=scope1+scope2")
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&token_type=bearer"))
	}))
	defer ts.Close()

	cfg := apidef.ClientCredentials{
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
					ClientCredentials: &cfg,
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
