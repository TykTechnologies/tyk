//go:build ee || dev

package gateway

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/test"
)

func TestUpstreamOAuthJWTBearer(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	_, _, combinedPEM, cert := crypto.GenCertificate(&x509.Certificate{}, false)
	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "")
	require.NoError(t, err)
	t.Cleanup(func() { ts.Gw.CertificateManager.Delete(certID, "") })
	pub := cert.Leaf
	if pub == nil {
		pub, err = x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
	}

	var idpCalls int32
	idpStatus, idpError := http.StatusOK, ""
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&idpCalls, 1)
		require.NoError(t, r.ParseForm())
		assert.Equal(t, oas.OAuth2GrantTypeJWTBearer, r.PostForm.Get("grant_type"))

		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(r.PostForm.Get("assertion"), claims, func(tok *jwt.Token) (interface{}, error) {
			assert.Equal(t, jwt.SigningMethodRS256, tok.Method)
			return pub.PublicKey, nil
		})
		assert.NoError(t, err)
		assert.Equal(t, "consumer-key", claims["iss"])
		assert.Equal(t, "user@example.com", claims["sub"])
		assert.Equal(t, "https://login.example.com", claims["aud"])

		w.Header().Set("Content-Type", "application/json")
		if idpStatus != http.StatusOK {
			w.WriteHeader(idpStatus)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": idpError})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "idp-token", "token_type": "Bearer", "expires_in": 600})
	}))
	t.Cleanup(idp.Close)

	var upstreamAuth atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	load := func(apiID, cert string) {
		oasAPI := getSampleOASAPI()
		ext := oasAPI.GetTykExtension()
		ext.Info.ID = apiID
		ext.Server.ListenPath = oas.ListenPath{Value: "/" + apiID + "/", Strip: true}
		ext.Upstream.URL = upstream.URL
		ext.Upstream.Authentication = &oas.UpstreamAuth{
			Enabled: true,
			OAuth: &oas.UpstreamOAuth{
				Enabled:               true,
				AllowedAuthorizeTypes: []string{apidef.OAuthAuthorizationTypeJWTBearer},
				JWTBearer: &oas.UpstreamOAuthJWTBearer{
					TokenURL: idp.URL,
					CertID:   cert,
					Issuer:   "consumer-key",
					Subject:  "user@example.com",
					Audience: "https://login.example.com",
				},
			},
		}
		oasAPI.SetTykExtension(ext)

		var def apidef.APIDefinition
		oasAPI.ExtractTo(&def)
		def.IsOAS = true
		def.UseKeylessAccess = true
		ts.Gw.LoadAPI(&APISpec{APIDefinition: &def, OAS: oasAPI})
	}

	t.Run("exchanges signed JWT and sends bearer token upstream", func(t *testing.T) {
		atomic.StoreInt32(&idpCalls, 0)
		load("jwt-ok", certID)

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/jwt-ok/", Code: http.StatusOK},
			{Path: "/jwt-ok/", Code: http.StatusOK},
		}...)
		assert.Equal(t, "Bearer idp-token", upstreamAuth.Load())
		assert.EqualValues(t, 1, atomic.LoadInt32(&idpCalls), "second request uses the cached token")
	})

	t.Run("missing signing certificate returns 500 without calling IdP", func(t *testing.T) {
		atomic.StoreInt32(&idpCalls, 0)
		upstreamAuth.Store("")
		load("jwt-nocert", "missing-cert")

		_, _ = ts.Run(t, test.TestCase{Path: "/jwt-nocert/", Code: http.StatusInternalServerError})
		assert.Zero(t, atomic.LoadInt32(&idpCalls))
		assert.Equal(t, "", upstreamAuth.Load(), "upstream is not called")
	})

	t.Run("IdP invalid_grant returns 401", func(t *testing.T) {
		atomic.StoreInt32(&idpCalls, 0)
		idpStatus, idpError = http.StatusBadRequest, "invalid_grant"
		t.Cleanup(func() { idpStatus, idpError = http.StatusOK, "" })
		upstreamAuth.Store("")
		load("jwt-rejected", certID)

		_, _ = ts.Run(t, test.TestCase{Path: "/jwt-rejected/", Code: http.StatusUnauthorized})
		assert.EqualValues(t, 1, atomic.LoadInt32(&idpCalls))
		assert.Equal(t, "", upstreamAuth.Load(), "upstream is not called")
	})
}
