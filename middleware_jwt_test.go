package main

import (
	//"encoding/base64"
	//"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/dgrijalva/jwt-go"
	//"strings"
	"testing"
	"time"

	"github.com/justinas/alice"
)

var jwtDef string = `

	{
		"name": "Tyk JWT API",
		"api_id": "76",
		"org_id": "default",
		"definition": {
			"location": "header",
			"key": "version"
		},
		"enable_jwt": true,
		"auth": {
			"auth_header_name": "authorization"
		},
		"version_data": {
			"not_versioned": true,
			"versions": {
				"Default": {
					"name": "Default",
					"use_extended_paths": true,
					"expires": "3000-01-02 15:04",
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					}
				}
			}
		},
		"proxy": {
			"listen_path": "/jwt_test",
			"target_url": "http://example.com/",
			"strip_listen_path": true
		}
	}

`

var jwtWithJWKDef string = `

	{
		"name": "Tyk JWT With JWK API",
		"api_id": "76",
		"org_id": "default",
		"definition": {
			"location": "header",
			"key": "version"
		},
		"enable_jwt": true,
		"jwt_source": "http://keyserver.tyk.io/test_jwk.json",
		"jwt_signing_method": "RSA",
		"jwt_identity_base_field": "user_id",
		"jwt_policy_field_name": "policy_id",
		"auth": {
			"auth_header_name": "authorization"
		},
		"version_data": {
			"not_versioned": true,
			"versions": {
				"Default": {
					"name": "Default",
					"use_extended_paths": true,
					"expires": "3000-01-02 15:04",
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					}
				}
			}
		},
		"proxy": {
			"listen_path": "/jwt_test",
			"target_url": "http://example.com/",
			"strip_listen_path": true
		}
	}

`

var jwtWithCentralDef string = `

	{
		"name": "Tyk JWT With JWK API",
		"api_id": "76",
		"org_id": "default",
		"definition": {
			"location": "header",
			"key": "version"
		},
		"enable_jwt": true,
		"jwt_source": "Ci0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeXFaNHJ3S0Y4cUNFeFM3a3BZNGMKbkphLzM3Rk1rSk5rYWxaM091c2xMQjBvUkw4VDRjOTRrZEY0YWVOelNGa1NlMm45OUlCSTZTc2w3OXZiZk1aYgordDA2TDBROTRrKy9QMzd4NysvUkpaaWZmNHkxVkdqcm5ybk1JMml1OWw0aUJCUll6Tm1HNmVibHJvRU1NV2xnCms1dHlzSGd4QjU5Q1NOSWNEOWdxazFoeDRuL0ZnT212S3NmUWdXSE5sUFNEVFJjV0dXR2hCMi9YZ05WWUcycE8KbFF4QVBxTGhCSGVxR1RYQmJQZkdGOWNIeml4cHNQcjZHdGJ6UHdoc1EvOGJQeG9KN2hkZm4rcnp6dGtzM2Q2KwpIV1VSY3lOVExSZTBtalhqamVlOVo2K2daK0grZlM0cG5QOXRxVDdJZ1U2ZVBVV1Rwam9pUHRMZXhnc0FhL2N0CmpRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=",
		"jwt_signing_method": "RSA",
		"jwt_identity_base_field": "user_id",
		"jwt_policy_field_name": "policy_id",
		"auth": {
			"auth_header_name": "authorization"
		},
		"version_data": {
			"not_versioned": true,
			"versions": {
				"Default": {
					"name": "Default",
					"use_extended_paths": true,
					"expires": "3000-01-02 15:04",
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					}
				}
			}
		},
		"proxy": {
			"listen_path": "/jwt_test",
			"target_url": "http://example.com/",
			"strip_listen_path": true
		}
	}

`

var jwtWithCentralDefNoPolicyBaseField string = `

	{
		"name": "Tyk JWT With JWK API",
		"api_id": "76",
		"org_id": "default",
		"definition": {
			"location": "header",
			"key": "version"
		},
		"enable_jwt": true,
		"jwt_source": "Ci0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeXFaNHJ3S0Y4cUNFeFM3a3BZNGMKbkphLzM3Rk1rSk5rYWxaM091c2xMQjBvUkw4VDRjOTRrZEY0YWVOelNGa1NlMm45OUlCSTZTc2w3OXZiZk1aYgordDA2TDBROTRrKy9QMzd4NysvUkpaaWZmNHkxVkdqcm5ybk1JMml1OWw0aUJCUll6Tm1HNmVibHJvRU1NV2xnCms1dHlzSGd4QjU5Q1NOSWNEOWdxazFoeDRuL0ZnT212S3NmUWdXSE5sUFNEVFJjV0dXR2hCMi9YZ05WWUcycE8KbFF4QVBxTGhCSGVxR1RYQmJQZkdGOWNIeml4cHNQcjZHdGJ6UHdoc1EvOGJQeG9KN2hkZm4rcnp6dGtzM2Q2KwpIV1VSY3lOVExSZTBtalhqamVlOVo2K2daK0grZlM0cG5QOXRxVDdJZ1U2ZVBVV1Rwam9pUHRMZXhnc0FhL2N0CmpRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=",
		"jwt_signing_method": "RSA",
		"jwt_identity_base_field": "user_id",
		"jwt_client_base_field": "azp",
		"auth": {
			"auth_header_name": "authorization"
		},
		"version_data": {
			"not_versioned": true,
			"versions": {
				"Default": {
					"name": "Default",
					"use_extended_paths": true,
					"expires": "3000-01-02 15:04",
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					}
				}
			}
		},
		"proxy": {
			"listen_path": "/jwt_test",
			"target_url": "http://example.com/",
			"strip_listen_path": true
		}
	}

`

const JWTSECRET string = "9879879878787878"

// openssl genrsa -out app.rsa
const JWTRSA_PRIVKEY string = `
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
const JWTRSA_PUBKEY string = `
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

func createJWTSession() SessionState {
	var thisSession SessionState
	thisSession.Rate = 1000000.0
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix() - 10
	thisSession.Per = 1.0
	thisSession.Expires = 0
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix() + 20
	thisSession.QuotaRemaining = 1
	thisSession.QuotaMax = -1
	thisSession.JWTData.Secret = JWTSECRET

	return thisSession
}

func createJWTSessionWithRSA() SessionState {
	var thisSession SessionState
	thisSession.Rate = 1000000.0
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix() - 10
	thisSession.Per = 1.0
	thisSession.Expires = 0
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix() + 20
	thisSession.QuotaRemaining = 1
	thisSession.QuotaMax = -1
	thisSession.JWTData.Secret = JWTRSA_PUBKEY

	return thisSession
}

func createJWTSessionWithRSAWithPolicy() SessionState {
	var thisSession SessionState
	thisSession.Rate = 1000000.0
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix() - 10
	thisSession.Per = 1.0
	thisSession.Expires = 0
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix() + 20
	thisSession.QuotaRemaining = 1
	thisSession.QuotaMax = -1
	thisSession.ApplyPolicyID = "987654321"

	return thisSession
}

func getJWTChain(spec APISpec) http.Handler {
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	remote, _ := url.Parse("http://example.com/")
	proxy := TykNewSingleHostReverseProxy(remote, &spec)
	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, &spec))
	tykMiddleware := &TykMiddleware{&spec, proxy}
	chain := alice.New(
		CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&JWTMiddleware{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware),
		CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

	return chain
}

func TestJWTSessionHMAC(t *testing.T) {
	var thisTokenKID string = randSeq(10)
	spec := createDefinitionFromString(jwtDef)
	spec.JWTSigningMethod = "hmac"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createJWTSession()
	spec.SessionManager.UpdateSession(thisTokenKID, thisSession, 60)

	// Create the token
	token := jwt.New(jwt.SigningMethodHS256)
	// Set the token ID
	token.Header["kid"] = thisTokenKID
	log.Info("Kid is: ", thisTokenKID)
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString([]byte(JWTSECRET))
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)
	req.Header.Add("authorization", tokenString)

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func TestJWTSessionRSA(t *testing.T) {
	var thisTokenKID string = randSeq(10)
	spec := createDefinitionFromString(jwtDef)
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(thisTokenKID, thisSession, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = thisTokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)
	req.Header.Add("authorization", tokenString)

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func TestJWTSessionFailRSA_EmptyJWT(t *testing.T) {
	var thisTokenKID string = randSeq(10)
	spec := createDefinitionFromString(jwtDef)
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(thisTokenKID, thisSession, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = thisTokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)

	// Make it empty
	req.Header.Add("authorization", "")

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Error("Initial request failed with non-400 code, was: \n", recorder.Code)
	}
}

func TestJWTSessionFailRSA_NoAuthHeader(t *testing.T) {
	var thisTokenKID string = randSeq(10)
	spec := createDefinitionFromString(jwtDef)
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(thisTokenKID, thisSession, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = thisTokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Error("Initial request failed with non-400 code, was: \n", recorder.Code)
	}
}

func TestJWTSessionFailRSA_MalformedJWT(t *testing.T) {
	var thisTokenKID string = randSeq(10)
	spec := createDefinitionFromString(jwtDef)
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(thisTokenKID, thisSession, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = thisTokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)

	// Make it empty
	req.Header.Add("authorization", tokenString+"ajhdkjhsdfkjashdkajshdkajhsdkajhsd")

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Initial request failed with non-403 code, was: \n", recorder.Code)
	}
}

func TestJWTSessionFailRSA_MalformedJWT_NOTRACK(t *testing.T) {
	var thisTokenKID string = randSeq(10)
	spec := createDefinitionFromString(jwtDef)
	spec.DoNotTrack = true
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(thisTokenKID, thisSession, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = thisTokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)

	// Make it empty
	req.Header.Add("authorization", tokenString+"ajhdkjhsdfkjashdkajshdkajhsdkajhsd")

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Initial request failed with non-403 code, was: \n", recorder.Code)
	}
}

func TestJWTSessionFailRSA_WrongJWT(t *testing.T) {
	var thisTokenKID string = randSeq(10)
	spec := createDefinitionFromString(jwtDef)
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(thisTokenKID, thisSession, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = thisTokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)

	// Make it empty
	req.Header.Add("authorization", "123")

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Initial request failed with non-403 code, was: \n", recorder.Code)
	}
}

func TestJWTSessionRSABearer(t *testing.T) {
	var thisTokenKID string = randSeq(10)
	spec := createDefinitionFromString(jwtDef)
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createJWTSessionWithRSA()
	spec.SessionManager.ResetQuota(thisTokenKID, thisSession)
	spec.SessionManager.UpdateSession(thisTokenKID, thisSession, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = thisTokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)
	req.Header.Add("authorization", "Bearer "+tokenString)

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func TestJWTSessionRSABearerInvalid(t *testing.T) {
	var thisTokenKID string = randSeq(10)
	spec := createDefinitionFromString(jwtDef)
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createJWTSessionWithRSA()
	spec.SessionManager.UpdateSession(thisTokenKID, thisSession, 60)

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = thisTokenKID
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)
	// add a colon here
	req.Header.Add("authorization", "Bearer: "+tokenString)

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Initial request failed with !=403 code, should have failed!: \n", recorder.Code)
	}
}

func TestJWTSessionRSAWithRawSourceOnWithClientID(t *testing.T) {
	spec := createDefinitionFromString(jwtWithCentralDefNoPolicyBaseField)
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)

	thisTokenID := "1234567891010101"
	thisSession := createJWTSessionWithRSAWithPolicy()
	spec.SessionManager.ResetQuota(thisTokenID, thisSession)
	spec.SessionManager.UpdateSession(thisTokenID, thisSession, 60)

	Policies["987654321"] = Policy{
		ID:               "987654321",
		OrgID:            "default",
		Rate:             1000.0,
		Per:              1.0,
		QuotaMax:         -1,
		QuotaRenewalRate: -1,
		AccessRights: map[string]AccessDefinition{"76": {
			APIName:  "Test",
			APIID:    "76",
			Versions: []string{"default"},
		}},
		Active:       true,
		KeyExpiresIn: 60,
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["user_id"] = randSeq(10)
	token.Claims.(jwt.MapClaims)["azp"] = thisTokenID
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)
	// add a colon here
	req.Header.Add("authorization", "Bearer "+tokenString)

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have passed!: ", recorder.Code)
	}
}

func TestJWTSessionRSAWithRawSource(t *testing.T) {
	spec := createDefinitionFromString(jwtWithCentralDef)
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)

	Policies["987654321"] = Policy{
		ID:               "987654321",
		OrgID:            "default",
		Rate:             1000.0,
		Per:              1.0,
		QuotaMax:         -1,
		QuotaRenewalRate: -1,
		AccessRights:     map[string]AccessDefinition{},
		Active:           true,
		KeyExpiresIn:     60,
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = "12345"
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["user_id"] = randSeq(10)
	token.Claims.(jwt.MapClaims)["policy_id"] = "987654321"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)
	// add a colon here
	req.Header.Add("authorization", "Bearer "+tokenString)

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have passed!: ", recorder.Code)
	}
}

func TestJWTSessionRSAWithRawSourceInvalidPolicyID(t *testing.T) {
	spec := createDefinitionFromString(jwtWithCentralDef)
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)

	Policies["987654321"] = Policy{
		ID:               "987654321",
		OrgID:            "default",
		Rate:             1000.0,
		Per:              1.0,
		QuotaMax:         -1,
		QuotaRenewalRate: -1,
		AccessRights:     map[string]AccessDefinition{},
		Active:           true,
		KeyExpiresIn:     60,
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = "12345"
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["user_id"] = randSeq(10)
	token.Claims.(jwt.MapClaims)["policy_id"] = "1234567898978788"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	//log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)
	// add a colon here
	req.Header.Add("authorization", "Bearer "+tokenString)

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Initial request failed with non-403 code, should have failed!: ", recorder.Code)
	}
}

func TestJWTSessionRSAWithJWK(t *testing.T) {
	spec := createDefinitionFromString(jwtWithJWKDef)
	spec.JWTSigningMethod = "rsa"
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)

	Policies["987654321"] = Policy{
		ID:               "987654321",
		OrgID:            "default",
		Rate:             1000.0,
		Per:              1.0,
		QuotaMax:         -1,
		QuotaRenewalRate: -1,
		AccessRights:     map[string]AccessDefinition{},
		Active:           true,
		KeyExpiresIn:     60,
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod("RS512"))
	// Set the token ID
	token.Header["kid"] = "12345"
	// Set some claims
	token.Claims.(jwt.MapClaims)["foo"] = "bar"
	token.Claims.(jwt.MapClaims)["user_id"] = randSeq(10)
	token.Claims.(jwt.MapClaims)["policy_id"] = "987654321"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	signKey, getSignErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(JWTRSA_PRIVKEY))
	if getSignErr != nil {
		log.Error("Couldn't extract private key: ")
		t.Fatal(getSignErr)
	}
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		log.Error("Couldn't create JWT token: ")
		t.Fatal(err)
	}
	//log.Info(tokenString)

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest("GET", "/jwt_test/?"+param.Encode(), nil)
	// add a colon here
	req.Header.Add("authorization", "Bearer "+tokenString)

	if err != nil {
		log.Error("Problem generating the test token: ", err)
	}

	chain := getJWTChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have passed!: ", recorder.Code)
	}
}
