package main

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

const jwtSecret = "9879879878787878"

// openssl genrsa -out app.rsa
const jwtRSAPrivKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyqZ4rwKF8qCExS7kpY4cnJa/37FMkJNkalZ3OuslLB0oRL8T
4c94kdF4aeNzSFkSe2n99IBI6Ssl79vbfMZb+t06L0Q94k+/P37x7+/RJZiff4y1
VGjrnrnMI2iu9l4iBBRYzNmG6eblroEMMWlgk5tysHgxB59CSNIcD9gqk1hx4n/F
gOmvKsfQgWHNlPSDTRcWGWGhB2/XgNVYG2pOlQxAPqLhBHeqGTXBbPfGF9cHzixp
sPr6GtbzPwhsQ/8bPxoJ7hdfn+rzztks3d6+HWURcyNTLRe0mjXjjee9Z6+gZ+H+
fS4pnP9tqT7IgU6ePUWTpjoiPtLexgsAa/ctjQIDAQABAoIBAECWvnBJRZgHQUn3
oDiECup9wbnyMI0D7UVXObk1qSteP69pl1SpY6xWLyLQs7WjbhiXt7FuEc7/SaAh
Wttx/W7/g8P85Bx1fmcmdsYakXaCJpPorQKyTibQ4ReIDfvIFN9n/MWNr0ptpVbx
GonFJFrneK52IGplgCLllLwYEbnULYcJc6E25Ro8U2gQjF2r43PDa07YiDrmB/GV
QQW4HTo+CA9rdK0bP8GpXgc0wpmBhx/t/YdnDg6qhzyUMk9As7JrAzYPjHO0cRun
vhA/aG/mdMmRumY75nj7wB5U5DgstsN2ER75Pjr1xe1knftIyNm15AShCPfLaLGo
dA2IpwECgYEA5E8h6ssa7QroCGwp/N0wSJW41hFYGygbOEg6yPWTJkqmMZVduD8X
/KFqJK4LcIbFQuR28+hWJpHm/RF1AMRhbbWkAj6h02gv5izFwDiFKev5paky4Evg
G8WfUOmSZ1D+fVxwaoG0OaRZpCovUTxYig3xrI659DMeKqpQ7e8l9ekCgYEA4zql
l4P4Dn0ydr+TI/s4NHIQHkaLQAVk3OWwyKowijXd8LCtuZRA1NKSpqQ4ZXi0B17o
9zzF5jEUjws3qWv4PKWdxJu3y+h/etsg7wxUeNizbY2ooUGeMbk0tWxJihbgaI7E
XxLIT50F3Ky4EJ2cUL9GmJ+gLCw0KIaVbkiyYAUCgYEA0WyVHB76r/2VIkS1rzHm
HG7ageKfAyoi7dmzsqsxM6q+EDWHJn8Zra8TAlp0O+AkClwvkUTJ4c9sJy9gODfr
dwtrSnPRVW74oRbovo4Z+H5xHbi65mwzQsZggYP/u63cA3pL1Cbt/wH3CFN52/aS
8PAhg7vYb1yEi3Z3jgoUtCECgYEAhSPX4u9waQzyhKG7lVmdlR1AVH0BGoIOl1/+
NZWC23i0klLzd8lmM00uoHWYldwjoC38UuFJE5eudCIeeybITMC9sHWNO+z+xP2g
TnDrDePrPkXCiLnp9ziNqb/JVyAQXTNJ3Gsk84EN7j9Fmna/IJDyzHq7XyaHaTdy
VyxBWAECgYEA4jYS07bPx5UMhKiMJDqUmDfLNFD97XwPoJIkOdn6ezqeOSmlmo7t
jxHLbCmsDOAsCU/0BlLXg9wMU7n5QKSlfTVGok/PU0rq2FUXQwyKGnellrqODwFQ
YGivtXBGXk1hlVYlje1RB+W6RQuDAegI5h8vl8pYJS9JQH0wjatsDaE=
-----END RSA PRIVATE KEY-----
`

// openssl rsa -in app.rsa -pubout > app.rsa.pub
const jwtRSAPubKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyqZ4rwKF8qCExS7kpY4c
nJa/37FMkJNkalZ3OuslLB0oRL8T4c94kdF4aeNzSFkSe2n99IBI6Ssl79vbfMZb
+t06L0Q94k+/P37x7+/RJZiff4y1VGjrnrnMI2iu9l4iBBRYzNmG6eblroEMMWlg
k5tysHgxB59CSNIcD9gqk1hx4n/FgOmvKsfQgWHNlPSDTRcWGWGhB2/XgNVYG2pO
lQxAPqLhBHeqGTXBbPfGF9cHzixpsPr6GtbzPwhsQ/8bPxoJ7hdfn+rzztks3d6+
HWURcyNTLRe0mjXjjee9Z6+gZ+H+fS4pnP9tqT7IgU6ePUWTpjoiPtLexgsAa/ct
jQIDAQAB
-----END PUBLIC KEY-----
`

func createJWTSession() *user.SessionState {
	session := new(user.SessionState)
	session.Rate = 1000000.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix() - 10
	session.Per = 1.0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix() + 20
	session.QuotaRemaining = 1
	session.QuotaMax = -1
	session.JWTData.Secret = jwtSecret
	return session
}

func createJWTSessionWithRSA() *user.SessionState {
	session := createJWTSession()
	session.JWTData.Secret = jwtRSAPubKey
	return session
}

func createJWTSessionWithRSAWithPolicy(policyID string) *user.SessionState {
	session := createJWTSessionWithRSA()
	session.SetPolicies(policyID)
	return session
}

// JWTSessionHMAC

func prepareJWTSessionHMAC(tb testing.TB) string {
	spec := buildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.JWTSigningMethod = "hmac"
		spec.EnableJWT = true
		spec.Proxy.ListenPath = "/"
	})[0]

	session := createJWTSession()
	tokenKID := testKey(tb, "token")
	spec.SessionManager.UpdateSession(tokenKID, session, 60, false)

	jwtToken := createJWKTokenHMAC(func(t *jwt.Token) {
		t.Header["kid"] = tokenKID
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	return jwtToken
}

func TestJWTSessionHMAC(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	jwtToken := prepareJWTSessionHMAC(t)

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT signed with HMAC", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	})
}

func BenchmarkJWTSessionHMAC(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	jwtToken := prepareJWTSessionHMAC(b)

	authHeaders := map[string]string{"authorization": jwtToken}
	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	}
}

// JWTSessionRSA
func prepareJWTSessionRSA(tb testing.TB) (*APISpec, string) {
	spec := buildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.JWTSigningMethod = "rsa"
		spec.EnableJWT = true
		spec.Proxy.ListenPath = "/"
	})[0]

	session := createJWTSessionWithRSA()
	tokenKID := testKey(tb, "token")
	spec.SessionManager.UpdateSession(tokenKID, session, 60, false)

	jwtToken := createJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = tokenKID
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	return spec, jwtToken
}

func TestJWTSessionRSA(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	_, jwtToken := prepareJWTSessionRSA(t)

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	})
}

func BenchmarkJWTSessionRSA(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	_, jwtToken := prepareJWTSessionRSA(b)

	authHeaders := map[string]string{"authorization": jwtToken}
	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	}
}

func TestJWTSessionFailRSA_EmptyJWT(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	prepareJWTSessionRSA(t)

	authHeaders := map[string]string{"authorization": ""}
	t.Run("Request with empty authorization header", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 400,
		})
	})
}

func TestJWTSessionFailRSA_NoAuthHeader(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	prepareJWTSessionRSA(t)

	authHeaders := map[string]string{}
	t.Run("Request without authorization header", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 400,
		})
	})
}

func TestJWTSessionFailRSA_MalformedJWT(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	_, jwtToken := prepareJWTSessionRSA(t)

	authHeaders := map[string]string{"authorization": jwtToken + "ajhdkjhsdfkjashdkajshdkajhsdkajhsd"}
	t.Run("Request with malformed JWT", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 403,
		})
	})
}

func TestJWTSessionFailRSA_MalformedJWT_NOTRACK(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec, jwtToken := prepareJWTSessionRSA(t)
	spec.DoNotTrack = true

	authHeaders := map[string]string{"authorization": jwtToken + "ajhdkjhsdfkjashdkajshdkajhsdkajhsd"}
	t.Run("Request with malformed JWT no track", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 403,
		})
	})
}

func TestJWTSessionFailRSA_WrongJWT(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	prepareJWTSessionRSA(t)

	authHeaders := map[string]string{"authorization": "123"}
	t.Run("Request with invalid JWT", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 403,
		})
	})
}

// TestJWTSessionRSABearer

func prepareJWTSessionRSABearer(tb testing.TB) string {
	spec := buildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.JWTSigningMethod = "rsa"
		spec.EnableJWT = true
		spec.Proxy.ListenPath = "/"
	})[0]

	session := createJWTSessionWithRSA()
	tokenKID := testKey(tb, "token")
	spec.SessionManager.UpdateSession(tokenKID, session, 60, false)

	jwtToken := createJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = tokenKID
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	return jwtToken
}

func TestJWTSessionRSABearer(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSABearer(t)

	authHeaders := map[string]string{"authorization": "Bearer " + jwtToken}
	t.Run("Request with valid Bearer", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	})
}

func BenchmarkJWTSessionRSABearer(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSABearer(b)

	authHeaders := map[string]string{"authorization": "Bearer " + jwtToken}

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	}
}

func TestJWTSessionRSABearerInvalid(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSABearer(t)

	authHeaders := map[string]string{"authorization": "Bearer: " + jwtToken} // extra ":"
	t.Run("Request with invalid Bearer", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 403,
		})
	})
}

// JWTSessionRSAWithRawSourceOnWithClientID

func prepareJWTSessionRSAWithRawSourceOnWithClientID() string {
	spec := buildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "777888"
		spec.OrgID = "default"
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = "rsa"
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTClientIDBaseField = "azp"
		spec.Proxy.ListenPath = "/"
	})[0]

	policyID := createPolicy(func(p *user.Policy) {
		p.OrgID = "default"
		p.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIName:  spec.APIDefinition.Name,
				APIID:    spec.APIID,
				Versions: []string{"default"},
			},
		}
	})

	tokenID := "1234567891010101"
	session := createJWTSessionWithRSAWithPolicy(policyID)

	spec.SessionManager.ResetQuota(tokenID, session)
	spec.SessionManager.UpdateSession(tokenID, session, 60, false)

	jwtToken := createJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["azp"] = tokenID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	return jwtToken
}

func TestJWTSessionRSAWithRawSourceOnWithClientID(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithRawSourceOnWithClientID()
	authHeaders := map[string]string{"authorization": jwtToken}

	t.Run("Initial request with no policy base field in JWT", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	})
}

func BenchmarkJWTSessionRSAWithRawSourceOnWithClientID(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithRawSourceOnWithClientID()
	authHeaders := map[string]string{"authorization": jwtToken}

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	}
}

// JWTSessionRSAWithRawSource

func prepareJWTSessionRSAWithRawSource() string {
	buildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = "rsa"
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})

	pID := createPolicy()

	jwtToken := createJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	return jwtToken
}

func TestJWTSessionRSAWithRawSource(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithRawSource()

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Initial request with invalid policy", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	})
}

func BenchmarkJWTSessionRSAWithRawSource(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithRawSource()

	authHeaders := map[string]string{"authorization": jwtToken}

	for i := 0; i < b.N; i++ {
		ts.Run(
			b,
			test.TestCase{
				Headers: authHeaders,
				Code:    200,
			},
		)
	}
}

func TestJWTSessionRSAWithRawSourceInvalidPolicyID(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := buildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = "rsa"
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})[0]

	loadAPI(spec)

	createPolicy()

	jwtToken := createJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["policy_id"] = "abcxyz"
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Initial request with invalid policy", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 403,
		})
	})
}

func TestJWTExistingSessionRSAWithRawSourceInvalidPolicyID(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := buildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = "rsa"
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})[0]

	loadAPI(spec)

	p1ID := createPolicy()

	jwtToken := createJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["policy_id"] = p1ID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Initial request with valid policy", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	})

	// put in JWT invalid policy ID and do request again
	jwtTokenInvalidPolicy := createJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["policy_id"] = "abcdef"
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders = map[string]string{"authorization": jwtTokenInvalidPolicy}
	t.Run("Request with invalid policy in JWT", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 403,
		})
	})
}

func TestJWTExistingSessionRSAWithRawSourcePolicyIDChanged(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := buildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = "rsa"
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})[0]

	loadAPI(spec)

	p1ID := createPolicy()
	p2ID := createPolicy()

	jwtToken := createJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["policy_id"] = p1ID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Initial request with 1st policy", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	})

	// put in JWT another valid policy ID and do request again
	jwtTokenAnotherPolicy := createJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["policy_id"] = p2ID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders = map[string]string{"authorization": jwtTokenAnotherPolicy}
	t.Run("Request with new valid policy in JWT", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	})
}

// JWTSessionRSAWithJWK

func prepareJWTSessionRSAWithJWK() string {
	buildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = "rsa"
		spec.JWTSource = testHttpJWK
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})

	pID := createPolicy()
	jwtToken := createJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	return jwtToken
}

func TestJWTSessionRSAWithJWK(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithJWK()
	authHeaders := map[string]string{"authorization": jwtToken}

	t.Run("JWTSessionRSAWithJWK", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	})
}

func BenchmarkJWTSessionRSAWithJWK(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithJWK()
	authHeaders := map[string]string{"authorization": jwtToken}

	for i := 0; i < b.N; i++ {
		ts.Run(
			b,
			test.TestCase{
				Headers: authHeaders,
				Code:    200,
			},
		)
	}
}

// JWTSessionRSAWithEncodedJWK

func prepareJWTSessionRSAWithEncodedJWK() (*APISpec, string) {
	spec := buildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = "rsa"
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})[0]

	pID := createPolicy()
	jwtToken := createJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		// Set some claims
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	return spec, jwtToken
}

func TestJWTSessionRSAWithEncodedJWK(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec, jwtToken := prepareJWTSessionRSAWithEncodedJWK()

	authHeaders := map[string]string{"authorization": jwtToken}

	t.Run("Direct JWK URL", func(t *testing.T) {
		spec.JWTSource = testHttpJWK
		loadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	})

	t.Run("Base64 JWK URL", func(t *testing.T) {
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(testHttpJWK))
		loadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 200,
		})
	})
}

func BenchmarkJWTSessionRSAWithEncodedJWK(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	spec, jwtToken := prepareJWTSessionRSAWithEncodedJWK()
	spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(testHttpJWK))

	loadAPI(spec)

	authHeaders := map[string]string{"authorization": jwtToken}

	for i := 0; i < b.N; i++ {
		ts.Run(
			b,
			test.TestCase{
				Headers: authHeaders,
				Code:    200,
			},
		)
	}
}
