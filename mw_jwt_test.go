package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/justinas/alice"

	"github.com/TykTechnologies/tyk/user"
)

const jwtDef = `{
	"api_id": "76",
	"org_id": "default",
	"enable_jwt": true,
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/jwt_test",
		"target_url": "` + testHttpAny + `"
	}
}`

const jwtWithJWKDef = `{
	"api_id": "76",
	"org_id": "default",
	"enable_jwt": true,
	"jwt_source": "` + testHttpJWK + `",
	"jwt_signing_method": "RSA",
	"jwt_identity_base_field": "user_id",
	"jwt_policy_field_name": "policy_id",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/jwt_test",
		"target_url": "` + testHttpAny + `"
	}
}`

const jwtWithEncodedJWKDef = `{
	"api_id": "76",
	"org_id": "default",
	"enable_jwt": true,
	"jwt_source": "` + testHttpEncodedJWK + `",
	"jwt_signing_method": "RSA",
	"jwt_identity_base_field": "user_id",
	"jwt_policy_field_name": "policy_id",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/jwt_test",
		"target_url": "` + testHttpAny + `"
	}
}`

const jwtWithCentralDef = `{
	"api_id": "76",
	"org_id": "default",
	"enable_jwt": true,
	"jwt_source": "Ci0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeXFaNHJ3S0Y4cUNFeFM3a3BZNGMKbkphLzM3Rk1rSk5rYWxaM091c2xMQjBvUkw4VDRjOTRrZEY0YWVOelNGa1NlMm45OUlCSTZTc2w3OXZiZk1aYgordDA2TDBROTRrKy9QMzd4NysvUkpaaWZmNHkxVkdqcm5ybk1JMml1OWw0aUJCUll6Tm1HNmVibHJvRU1NV2xnCms1dHlzSGd4QjU5Q1NOSWNEOWdxazFoeDRuL0ZnT212S3NmUWdXSE5sUFNEVFJjV0dXR2hCMi9YZ05WWUcycE8KbFF4QVBxTGhCSGVxR1RYQmJQZkdGOWNIeml4cHNQcjZHdGJ6UHdoc1EvOGJQeG9KN2hkZm4rcnp6dGtzM2Q2KwpIV1VSY3lOVExSZTBtalhqamVlOVo2K2daK0grZlM0cG5QOXRxVDdJZ1U2ZVBVV1Rwam9pUHRMZXhnc0FhL2N0CmpRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=",
	"jwt_signing_method": "RSA",
	"jwt_identity_base_field": "user_id",
	"jwt_policy_field_name": "policy_id",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/jwt_test",
		"target_url": "` + testHttpAny + `"
	}
}`

const jwtWithCentralDefNoPolicyBaseField = `{
	"api_id": "76",
	"org_id": "default",
	"enable_jwt": true,
	"jwt_source": "Ci0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeXFaNHJ3S0Y4cUNFeFM3a3BZNGMKbkphLzM3Rk1rSk5rYWxaM091c2xMQjBvUkw4VDRjOTRrZEY0YWVOelNGa1NlMm45OUlCSTZTc2w3OXZiZk1aYgordDA2TDBROTRrKy9QMzd4NysvUkpaaWZmNHkxVkdqcm5ybk1JMml1OWw0aUJCUll6Tm1HNmVibHJvRU1NV2xnCms1dHlzSGd4QjU5Q1NOSWNEOWdxazFoeDRuL0ZnT212S3NmUWdXSE5sUFNEVFJjV0dXR2hCMi9YZ05WWUcycE8KbFF4QVBxTGhCSGVxR1RYQmJQZkdGOWNIeml4cHNQcjZHdGJ6UHdoc1EvOGJQeG9KN2hkZm4rcnp6dGtzM2Q2KwpIV1VSY3lOVExSZTBtalhqamVlOVo2K2daK0grZlM0cG5QOXRxVDdJZ1U2ZVBVV1Rwam9pUHRMZXhnc0FhL2N0CmpRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=",
	"jwt_signing_method": "RSA",
	"jwt_identity_base_field": "user_id",
	"jwt_client_base_field": "azp",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/jwt_test",
		"target_url": "` + testHttpAny + `"
	}
}`

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

func createJWTSessionWithRSAWithPolicy() *user.SessionState {
	session := createJWTSessionWithRSA()
	session.SetPolicies("987654321")
	return session
}

func getJWTChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(testHttpAny)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{spec, proxy}
	chain := alice.New(mwList(
		&IPWhiteListMiddleware{baseMid},
		&JWTMiddleware{baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
		&KeyExpired{baseMid},
		&AccessRightsCheck{baseMid},
		&RateLimitAndQuotaCheck{baseMid},
	)...).Then(proxyHandler)
	return chain
}

func TestJWTSessionHMAC(t *testing.T) {
	tokenKID := testKey(t, "token")
	spec := createSpecTest(t, jwtDef)
	spec.JWTSigningMethod = "hmac"
	session := createJWTSession()
	spec.SessionManager.UpdateSession(tokenKID, session, 60)

	// Create the token
	token := jwt.New(jwt.SigningMethodHS256)
	// Set the token ID
	token.Header["kid"] = tokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)
	req.Header.Set("authorization", tokenString)

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func TestJWTSessionRSA(t *testing.T) {
	tokenKID := testKey(t, "token")
	spec := createSpecTest(t, jwtDef)
	spec.JWTSigningMethod = "rsa"
	session := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(tokenKID, session, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = tokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		t.Fatal("Couldn't extract private key: ", err)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)
	req.Header.Set("authorization", tokenString)

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func TestJWTSessionFailRSA_EmptyJWT(t *testing.T) {
	tokenKID := testKey(t, "token")
	spec := createSpecTest(t, jwtDef)
	spec.JWTSigningMethod = "rsa"
	session := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(tokenKID, session, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = tokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)

	// Make it empty
	req.Header.Set("authorization", "")

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Error("Initial request failed with non-400 code, was: \n", recorder.Code)
	}
}

func TestJWTSessionFailRSA_NoAuthHeader(t *testing.T) {
	tokenKID := testKey(t, "token")
	spec := createSpecTest(t, jwtDef)
	spec.JWTSigningMethod = "rsa"
	session := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(tokenKID, session, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = tokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Error("Initial request failed with non-400 code, was: \n", recorder.Code)
	}
}

func TestJWTSessionFailRSA_MalformedJWT(t *testing.T) {
	tokenKID := testKey(t, "token")
	spec := createSpecTest(t, jwtDef)
	spec.JWTSigningMethod = "rsa"
	session := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(tokenKID, session, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = tokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		t.Fatal("Couldn't extract private key: ", err)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)

	// Make it empty
	req.Header.Set("authorization", tokenString+"ajhdkjhsdfkjashdkajshdkajhsdkajhsd")

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Initial request failed with non-403 code, was: \n", recorder.Code)
	}
}

func TestJWTSessionFailRSA_MalformedJWT_NOTRACK(t *testing.T) {
	tokenKID := testKey(t, "token")
	spec := createSpecTest(t, jwtDef)
	spec.DoNotTrack = true
	spec.JWTSigningMethod = "rsa"
	session := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(tokenKID, session, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = tokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		t.Fatal("Couldn't extract private key: ", err)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)

	// Make it empty
	req.Header.Set("authorization", tokenString+"ajhdkjhsdfkjashdkajshdkajhsdkajhsd")

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Initial request failed with non-403 code, was: \n", recorder.Code)
	}
}

func TestJWTSessionFailRSA_WrongJWT(t *testing.T) {
	tokenKID := testKey(t, "token")
	spec := createSpecTest(t, jwtDef)
	spec.JWTSigningMethod = "rsa"
	session := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(tokenKID, session, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = tokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)

	// Make it empty
	req.Header.Set("authorization", "123")

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Initial request failed with non-403 code, was: \n", recorder.Code)
	}
}

func TestJWTSessionRSABearer(t *testing.T) {
	tokenKID := testKey(t, "token")
	spec := createSpecTest(t, jwtDef)
	spec.JWTSigningMethod = "rsa"
	session := createJWTSessionWithRSA()
	spec.SessionManager.ResetQuota(tokenKID, session)
	spec.SessionManager.UpdateSession(tokenKID, session, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = tokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		t.Fatal("Couldn't extract private key: ", err)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)
	req.Header.Set("authorization", "Bearer "+tokenString)

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func TestJWTSessionRSABearerInvalid(t *testing.T) {
	tokenKID := testKey(t, "token")
	spec := createSpecTest(t, jwtDef)
	spec.JWTSigningMethod = "rsa"
	session := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(tokenKID, session, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = tokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		t.Fatal("Couldn't extract private key: ", err)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)
	// add a colon here
	req.Header.Set("authorization", "Bearer: "+tokenString)

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Initial request failed with !=403 code, should have failed!: \n", recorder.Code)
	}
}

func TestJWTSessionRSAWithRawSourceOnWithClientID(t *testing.T) {
	spec := createSpecTest(t, jwtWithCentralDefNoPolicyBaseField)
	spec.JWTSigningMethod = "rsa"

	tokenID := "1234567891010101"
	session := createJWTSessionWithRSAWithPolicy()
	spec.SessionManager.ResetQuota(tokenID, session)
	spec.SessionManager.UpdateSession(tokenID, session, 60)

	policiesMu.Lock()
	policiesByID["987654321"] = user.Policy{
		ID:               "987654321",
		OrgID:            "default",
		Rate:             1000.0,
		Per:              1.0,
		QuotaMax:         -1,
		QuotaRenewalRate: -1,
		AccessRights: map[string]user.AccessDefinition{"76": {
			APIName:  "Test",
			APIID:    "76",
			Versions: []string{"default"},
		}},
		Active:       true,
		KeyExpiresIn: 60,
	}
	policiesMu.Unlock()

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["user_id"] = testKey(t, "token")
	token.Claims.(jwt.MapClaims)["azp"] = tokenID
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		t.Fatal("Couldn't extract private key: ", err)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)
	// add a colon here
	req.Header.Set("authorization", "Bearer "+tokenString)

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have passed!: ", recorder.Code)
	}
}

func TestJWTSessionRSAWithRawSource(t *testing.T) {
	spec := createSpecTest(t, jwtWithCentralDef)
	spec.JWTSigningMethod = "rsa"

	policiesMu.Lock()
	policiesByID["987654321"] = user.Policy{
		ID:               "987654321",
		OrgID:            "default",
		Rate:             1000.0,
		Per:              1.0,
		QuotaMax:         -1,
		QuotaRenewalRate: -1,
		AccessRights:     map[string]user.AccessDefinition{},
		Active:           true,
		KeyExpiresIn:     60,
	}
	policiesMu.Unlock()

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = "12345"
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["user_id"] = testKey(t, "token")
	token.Claims.(jwt.MapClaims)["policy_id"] = "987654321"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		t.Fatal("Couldn't extract private key: ", err)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)
	// add a colon here
	req.Header.Set("authorization", "Bearer "+tokenString)

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have passed!: ", recorder.Code)
	}
}

func TestJWTSessionRSAWithRawSourceInvalidPolicyID(t *testing.T) {
	spec := createSpecTest(t, jwtWithCentralDef)
	spec.JWTSigningMethod = "rsa"

	policiesMu.Lock()
	policiesByID["987654321"] = user.Policy{
		ID:               "987654321",
		OrgID:            "default",
		Rate:             1000.0,
		Per:              1.0,
		QuotaMax:         -1,
		QuotaRenewalRate: -1,
		AccessRights:     map[string]user.AccessDefinition{},
		Active:           true,
		KeyExpiresIn:     60,
	}
	policiesMu.Unlock()

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = "12345"
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["user_id"] = testKey(t, "token")
	token.Claims.(jwt.MapClaims)["policy_id"] = "1234567898978788"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		t.Fatal("Couldn't extract private key: ", err)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)
	// add a colon here
	req.Header.Set("authorization", "Bearer "+tokenString)

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Initial request failed with non-403 code, should have failed!: ", recorder.Code)
	}
}

func TestJWTExistingSessionRSAWithRawSourceInvalidPolicyID(t *testing.T) {
	spec := createSpecTest(t, jwtWithCentralDef)
	spec.JWTSigningMethod = "rsa"

	policiesMu.Lock()
	policiesByID["987654321"] = user.Policy{
		ID:               "987654321",
		OrgID:            "default",
		Rate:             1000.0,
		Per:              1.0,
		QuotaMax:         -1,
		QuotaRenewalRate: -1,
		AccessRights:     map[string]user.AccessDefinition{},
		Active:           true,
		KeyExpiresIn:     60,
	}
	policiesMu.Unlock()

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = "12345"
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["user_id"] = testKey(t, "token")
	token.Claims.(jwt.MapClaims)["policy_id"] = "987654321"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		t.Fatal("Couldn't extract private key: ", err)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)
	// add a colon here
	req.Header.Set("authorization", "Bearer "+tokenString)

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have passed!: ", recorder.Code)
	}

	// put JWT invalid policy ID and do request again
	token.Claims.(jwt.MapClaims)["policy_id"] = "abcdef"
	tokenString, err = token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder = httptest.NewRecorder()
	req2 := testReq(t, "GET", "/jwt_test/", nil)
	// add a colon here
	req2.Header.Set("authorization", "Bearer "+tokenString)

	chain.ServeHTTP(recorder, req2)

	if recorder.Code != 403 {
		t.Error("Initial request failed with non-403 code, should have failed!: ", recorder.Code)
	}

}

func TestJWTSessionRSAWithJWK(t *testing.T) {
	spec := createSpecTest(t, jwtWithJWKDef)
	spec.JWTSigningMethod = "rsa"

	policiesMu.Lock()
	policiesByID["987654321"] = user.Policy{
		ID:               "987654321",
		OrgID:            "default",
		Rate:             1000.0,
		Per:              1.0,
		QuotaMax:         -1,
		QuotaRenewalRate: -1,
		AccessRights:     map[string]user.AccessDefinition{},
		Active:           true,
		KeyExpiresIn:     60,
	}
	policiesMu.Unlock()

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = "12345"
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["user_id"] = testKey(t, "token")
	token.Claims.(jwt.MapClaims)["policy_id"] = "987654321"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		t.Fatal("Couldn't extract private key: ", err)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)
	// add a colon here
	req.Header.Set("authorization", "Bearer "+tokenString)

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have passed!: ", recorder.Code)
	}
}

func TestJWTSessionRSAWithEncodedJWK(t *testing.T) {
	spec := createSpecTest(t, jwtWithEncodedJWKDef)
	spec.JWTSigningMethod = "rsa"

	policiesMu.Lock()
	policiesByID["987654321"] = user.Policy{
		ID:               "987654321",
		OrgID:            "default",
		Rate:             1000.0,
		Per:              1.0,
		QuotaMax:         -1,
		QuotaRenewalRate: -1,
		AccessRights:     map[string]user.AccessDefinition{},
		Active:           true,
		KeyExpiresIn:     60,
	}
	policiesMu.Unlock()

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = "12345"
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["user_id"] = testKey(t, "token")
	token.Claims.(jwt.MapClaims)["policy_id"] = "987654321"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtRSAPrivKey))
	if err != nil {
		t.Fatal("Couldn't extract private key: ", err)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Fatal("Couldn't create JWT token: ", err)
	}

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/jwt_test/", nil)
	// add a colon here
	req.Header.Set("authorization", "Bearer "+tokenString)

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have passed!: ", recorder.Code)
	}
}
