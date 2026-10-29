package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// JWKS that go-jose v3 loaded but go-jose v4 rejects as a whole must keep
// loading after the upgrade. Behaviour is covered in detail by
// internal/jwkcompat; these tests check the Gateway uses it.

// rsaJWK returns an RSA public JWK. With padded, n uses base64url with "=" padding.
func rsaJWK(kid string, n *big.Int, padded bool) map[string]string {
	enc := base64.RawURLEncoding
	if padded {
		enc = base64.URLEncoding
	}
	return map[string]string{"kty": "RSA", "kid": kid, "n": enc.EncodeToString(n.Bytes()), "e": "AQAB"}
}

// largeModulus is an 8192-bit odd number, enough for an RSA public JWK.
func largeModulus() *big.Int {
	n := new(big.Int).Lsh(big.NewInt(1), 8191)
	return n.SetBit(n, 0, 1)
}

func jwksJSON(t *testing.T, keys ...map[string]string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]interface{}{"keys": keys})
	require.NoError(t, err)
	return data
}

func TestParseJWK_KeepsGoJoseV3Behaviour(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name     string
		jwks     []byte
		wantKids []string
	}{
		{
			name:     "RSA key over 4096 bits next to a normal key",
			jwks:     jwksJSON(t, rsaJWK("big", largeModulus(), false), rsaJWK("small", small.N, false)),
			wantKids: []string{"big", "small"},
		},
		{
			name:     "base64url values with = padding",
			jwks:     jwksJSON(t, rsaJWK("small", small.N, true)),
			wantKids: []string{"small"},
		},
		{
			name: "low-order Ed25519 key next to a normal key",
			jwks: jwksJSON(t,
				map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "ed", "x": base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
				rsaJWK("small", small.N, false)),
			wantKids: []string{"ed", "small"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set, err := parseJWK(tt.jwks)
			require.NoError(t, err)

			var kids []string
			for _, k := range set.Keys {
				kids = append(kids, k.KeyID)
			}
			assert.Equal(t, tt.wantKids, kids)
		})
	}
}

func TestJWTSessionRSAWithJWK_KeySetGoJoseV4Rejects(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := jwksJSON(t, rsaJWK("big", largeModulus(), false), rsaJWK("real", signingKey.N, true))
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwks)
	}))
	defer jwksServer.Close()

	const testAPIID = "jwkcompat-api"
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = jwksServer.URL
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
		spec.DisableRateLimit = true
		spec.DisableQuota = true
	})

	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			testAPIID: {
				APIName: "test-api-name",
			},
		}
	})

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"user_id":   "user",
		"policy_id": pID,
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "real"
	signed, err := token.SignedString(signingKey)
	require.NoError(t, err)

	_, _ = ts.Run(t, test.TestCase{
		Headers: map[string]string{"authorization": signed}, Code: http.StatusOK,
	})
}
