package gateway

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lonelycode/go-uuid/uuid"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

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

const jwtRSAPubKeyinvalid = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyqZ4rwKF8qCExS7kpY4c
nJa/37FMkJNkalZ3OuslLB0oRL8T4c94kdF4aeNzSFkSe2n99IBI6Ssl79vbfMZb
+t06L0Q94k+/P37x7+/RJZiff4y1VGjrnrnMI2iu9l4iBBRYzNmG6eblroEMMWlg
k5tysHgxB59CSNIcD9gqk1hx4n/FgOmvKsfQgWHNlPSDTRcWGWGhB2/XgNVYG2pO
lQxAPqLhBHeqGTXBbPfGF9cHzixpsPr6GtbzPwhsQ/8bPxoJ7hdfn+rzztks3d6+
HWURcyNTLRe0mjXjjee9Z6+gZ+H+fS4pnP9tqT7IgU6ePUWTpjoiPtLexgsAa/ct
jQIDAQAB!!!!
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

type JwtCreator func() *user.SessionState

func prepareGenericJWTSession(testName string, method string, claimName string, ApiSkipKid bool) (*APISpec, string) {
	tokenKID := testKey(testName, "token")

	var jwtToken string
	var sessionFunc JwtCreator
	switch method {
	default:
		log.Warningf("Signing method '%s' is not recognised, defaulting to HMAC signature", method)
		method = HMACSign
		fallthrough
	case HMACSign:
		sessionFunc = createJWTSession

		jwtToken = createJWKTokenHMAC(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)["foo"] = "bar"
			t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()

			if claimName != KID {
				t.Claims.(jwt.MapClaims)[claimName] = tokenKID
				t.Header[KID] = "ignore-this-id"
			} else {
				t.Header[KID] = tokenKID
			}
		})
	case RSASign:
		sessionFunc = createJWTSessionWithRSA

		jwtToken = CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)["foo"] = "bar"
			t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()

			if claimName != KID {
				t.Claims.(jwt.MapClaims)[claimName] = tokenKID
				t.Header[KID] = "ignore-this-id"
			} else {
				t.Header[KID] = tokenKID
			}
		})
	}

	spec := BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.JWTSigningMethod = method
		spec.EnableJWT = true
		spec.Proxy.ListenPath = "/"
		spec.JWTSkipKid = ApiSkipKid

		if claimName != KID {
			spec.JWTIdentityBaseField = claimName
		}
	})[0]
	spec.SessionManager.UpdateSession(tokenKID, sessionFunc(), 60, false)

	return spec, jwtToken

}

func TestJWTSessionHMAC(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//If we skip the check then the Id will be taken from SUB and the call will succeed
	_, jwtToken := prepareGenericJWTSession(t.Name(), HMACSign, KID, false)
	defer ResetTestConfig()

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT signed with HMAC", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func BenchmarkJWTSessionHMAC(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	//If we skip the check then the Id will be taken from SUB and the call will succeed
	_, jwtToken := prepareGenericJWTSession(b.Name(), HMACSign, KID, false)
	defer ResetTestConfig()

	authHeaders := map[string]string{"authorization": jwtToken}
	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	}
}

func TestJWTHMACIdInSubClaim(t *testing.T) {

	ts := StartTest()
	defer ts.Close()

	//Same as above
	_, jwtToken := prepareGenericJWTSession(t.Name(), HMACSign, SUB, true)
	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/HMAC/Id in SuB/Global-skip-kid/Api-skip-kid", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})

	// For backward compatibility, if the new config are not set, and the id is in the 'sub' claim while the 'kid' claim
	// in the header is not empty, then the jwt will return 403 - "Key not authorized:token invalid, key not found"
	_, jwtToken = prepareGenericJWTSession(t.Name(), HMACSign, SUB, false)
	authHeaders = map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/HMAC/Id in SuB/Global-dont-skip-kid/Api-dont-skip-kid", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: `Key not authorized:token invalid, key not found`,
		})
	})

	// Case where the gw always check the 'kid' claim first but if this JWTSkipCheckKidAsId is set on the api level,
	// then it'll work
	_, jwtToken = prepareGenericJWTSession(t.Name(), HMACSign, SUB, true)
	defer ResetTestConfig()
	authHeaders = map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/HMAC/Id in SuB/Global-dont-skip-kid/Api-skip-kid", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func TestJWTRSAIdInSubClaim(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	_, jwtToken := prepareGenericJWTSession(t.Name(), RSASign, SUB, true)
	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/RSA/Id in SuB/Global-skip-kid/Api-skip-kid", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})

	_, jwtToken = prepareGenericJWTSession(t.Name(), RSASign, SUB, false)
	authHeaders = map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/RSA/Id in SuB/Global-dont-skip-kid/Api-dont-skip-kid", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: `Key not authorized:token invalid, key not found`,
		})
	})

	_, jwtToken = prepareGenericJWTSession(t.Name(), RSASign, SUB, true)
	authHeaders = map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/RSA/Id in SuB/Global-dont-skip-kid/Api-skip-kid", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func TestJWTSessionRSA(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//default values, keep backward compatibility
	_, jwtToken := prepareGenericJWTSession(t.Name(), RSASign, KID, false)
	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func BenchmarkJWTSessionRSA(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	//default values, keep backward compatibility
	_, jwtToken := prepareGenericJWTSession(b.Name(), RSASign, KID, false)

	authHeaders := map[string]string{"authorization": jwtToken}
	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	}
}

func TestJWTSessionFailRSA_EmptyJWT(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//default values, same as before (keeps backward compatibility)
	prepareGenericJWTSession(t.Name(), RSASign, KID, false)

	authHeaders := map[string]string{"authorization": ""}
	t.Run("Request with empty authorization header", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: 400,
		})
	})
}

func TestJWTSessionFailRSA_NoAuthHeader(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//default values, same as before (keeps backward compatibility)
	prepareGenericJWTSession(t.Name(), RSASign, KID, false)

	authHeaders := map[string]string{}
	t.Run("Request without authorization header", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusBadRequest, BodyMatch: `Authorization field missing`,
		})
	})
}

func TestJWTSessionFailRSA_MalformedJWT(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//default values, same as before (keeps backward compatibility)
	_, jwtToken := prepareGenericJWTSession(t.Name(), RSASign, KID, false)

	authHeaders := map[string]string{"authorization": jwtToken + "ajhdkjhsdfkjashdkajshdkajhsdkajhsd"}
	t.Run("Request with malformed JWT", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: `Key not authorized:crypto/rsa: verification error`,
		})
	})
}

func TestJWTSessionFailRSA_MalformedJWT_NOTRACK(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//default values, same as before (keeps backward compatibility)
	spec, jwtToken := prepareGenericJWTSession(t.Name(), RSASign, KID, false)
	spec.DoNotTrack = true
	authHeaders := map[string]string{"authorization": jwtToken + "ajhdkjhsdfkjashdkajshdkajhsdkajhsd"}

	t.Run("Request with malformed JWT no track", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: `Key not authorized:crypto/rsa: verification error`,
		})
	})
}

func TestJWTSessionFailRSA_WrongJWT(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//default values, same as before (keeps backward compatibility)
	prepareGenericJWTSession(t.Name(), RSASign, KID, false)
	authHeaders := map[string]string{"authorization": "123"}

	t.Run("Request with invalid JWT", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: `Key not authorized:token contains an invalid number of segments`,
		})
	})
}

func TestJWTSessionRSABearer(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//default values, same as before (keeps backward compatibility)
	_, jwtToken := prepareGenericJWTSession(t.Name(), RSASign, KID, false)
	authHeaders := map[string]string{"authorization": "Bearer " + jwtToken}

	t.Run("Request with valid Bearer", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func BenchmarkJWTSessionRSABearer(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	//default values, same as before (keeps backward compatibility)
	_, jwtToken := prepareGenericJWTSession(b.Name(), RSASign, KID, false)
	authHeaders := map[string]string{"authorization": "Bearer " + jwtToken}

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	}
}

func TestJWTSessionRSABearerInvalid(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//default values, same as before (keeps backward compatibility)
	_, jwtToken := prepareGenericJWTSession(t.Name(), RSASign, KID, false)
	authHeaders := map[string]string{"authorization": "Bearer: " + jwtToken} // extra ":" makes the value invalid

	t.Run("Request with invalid Bearer", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: "Key not authorized:illegal base64 data at input byte 6",
		})
	})
}

func TestJWTSessionRSABearerInvalidTwoBears(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//default values, same as before (keeps backward compatibility)
	_, jwtToken := prepareGenericJWTSession(t.Name(), RSASign, KID, false)
	authHeaders1 := map[string]string{"authorization": "Bearer bearer" + jwtToken}

	t.Run("Request with Bearer bearer", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders1, Code: http.StatusForbidden,
		})
	})

	authHeaders2 := map[string]string{"authorization": "bearer Bearer" + jwtToken}

	t.Run("Request with bearer Bearer", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders2, Code: http.StatusForbidden,
		})
	})
}

// JWTSessionRSAWithRawSourceOnWithClientID

func prepareJWTSessionRSAWithRawSourceOnWithClientID(isBench bool) string {
	spec := BuildAndLoadAPI(func(spec *APISpec) {
		spec.OrgID = "default"
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTClientIDBaseField = "azp"
		spec.Proxy.ListenPath = "/"
	})[0]

	policyID := CreatePolicy(func(p *user.Policy) {
		p.OrgID = "default"
		p.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIName:  spec.APIDefinition.Name,
				APIID:    spec.APIID,
				Versions: []string{"default"},
			},
		}
	})

	tokenID := ""
	if isBench {
		tokenID = uuid.New()
	} else {
		tokenID = "1234567891010101"
	}
	session := createJWTSessionWithRSAWithPolicy(policyID)

	spec.SessionManager.ResetQuota(tokenID, session, false)
	spec.SessionManager.UpdateSession(tokenID, session, 60, false)

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["azp"] = tokenID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	return jwtToken
}

func TestJWTSessionRSAWithRawSourceOnWithClientID(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithRawSourceOnWithClientID(false)
	authHeaders := map[string]string{"authorization": jwtToken}

	t.Run("Initial request with no policy base field in JWT", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func BenchmarkJWTSessionRSAWithRawSourceOnWithClientID(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithRawSourceOnWithClientID(true)
	authHeaders := map[string]string{"authorization": jwtToken}

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	}
}

// JWTSessionRSAWithRawSource

func prepareJWTSessionRSAWithRawSource() string {
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})

	pID := CreatePolicy()

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	return jwtToken
}

func TestJWTSessionRSAWithRawSource(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithRawSource()

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Initial request with valid policy", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func BenchmarkJWTSessionRSAWithRawSource(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithRawSource()

	authHeaders := map[string]string{"authorization": jwtToken}

	for i := 0; i < b.N; i++ {
		ts.Run(
			b,
			test.TestCase{
				Headers: authHeaders,
				Code:    http.StatusOK,
			},
		)
	}
}

func TestJWTSessionRSAWithRawSourceInvalidPolicyID(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})[0]

	LoadAPI(spec)

	CreatePolicy()

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["policy_id"] = "abcxyz"
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Initial request with invalid policy", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: "key not authorized: no matching policy",
		})
	})
}

func TestJWTSessionExpiresAtValidationConfigs(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	pID := CreatePolicy()
	jwtAuthHeaderGen := func(skew time.Duration) map[string]string {
		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)["policy_id"] = pID
			t.Claims.(jwt.MapClaims)["user_id"] = "user123"
			t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(skew).Unix()
		})

		return map[string]string{"authorization": jwtToken}
	}

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})[0]

	// This test is successful by definition
	t.Run("Expiry_After_now--Valid_jwt", func(t *testing.T) {
		spec.JWTExpiresAtValidationSkew = 0 //Default value
		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(+time.Second), Code: http.StatusOK,
		})
	})

	// This test is successful by definition, so it's true also with skew, but just to avoid confusion.
	t.Run("Expiry_After_now-Add_skew--Valid_jwt", func(t *testing.T) {
		spec.JWTExpiresAtValidationSkew = 1
		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(+time.Second), Code: http.StatusOK,
		})
	})

	t.Run("Expiry_Before_now--Invalid_jwt", func(t *testing.T) {
		spec.JWTExpiresAtValidationSkew = 0 //Default value
		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers:   jwtAuthHeaderGen(-time.Second),
			Code:      http.StatusUnauthorized,
			BodyMatch: "Key not authorized: token has expired",
		})
	})

	t.Run("Expired_token-Before_now-Huge_skew--Valid_jwt", func(t *testing.T) {
		spec.JWTExpiresAtValidationSkew = 1000 // This value doesn't matter since validation is disabled
		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(-time.Second), Code: http.StatusOK,
		})
	})

	t.Run("Expired_token-Before_now-Add_skew--Valid_jwt", func(t *testing.T) {
		spec.JWTExpiresAtValidationSkew = 2
		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(-time.Second), Code: http.StatusOK,
		})
	})
}

func TestJWTSessionIssueAtValidationConfigs(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	pID := CreatePolicy()
	jwtAuthHeaderGen := func(skew time.Duration) map[string]string {
		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)["policy_id"] = pID
			t.Claims.(jwt.MapClaims)["user_id"] = "user123"
			t.Claims.(jwt.MapClaims)["iat"] = time.Now().Add(skew).Unix()
		})

		return map[string]string{"authorization": jwtToken}
	}

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = "rsa"
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})[0]

	// This test is successful by definition
	t.Run("IssuedAt_Before_now-no_skew--Valid_jwt", func(t *testing.T) {
		spec.JWTIssuedAtValidationSkew = 0

		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(-time.Second), Code: http.StatusOK,
		})
	})

	t.Run("Expiry_after_now--Invalid_jwt", func(t *testing.T) {
		spec.JWTExpiresAtValidationSkew = 0 //Default value

		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(-time.Second), Code: http.StatusOK,
		})
	})

	t.Run("IssueAt-After_now-no_skew--Invalid_jwt", func(t *testing.T) {
		spec.JWTIssuedAtValidationSkew = 0

		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers:   jwtAuthHeaderGen(+time.Minute),
			Code:      http.StatusUnauthorized,
			BodyMatch: "Key not authorized: token used before issued",
		})
	})

	t.Run("IssueAt--After_now-Huge_skew--valid_jwt", func(t *testing.T) {
		spec.JWTIssuedAtValidationSkew = 1000 // This value doesn't matter since validation is disabled
		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(+time.Second),
			Code:    http.StatusOK,
		})
	})

	// True by definition
	t.Run("IssueAt-Before_now-Add_skew--not_valid_jwt", func(t *testing.T) {
		spec.JWTIssuedAtValidationSkew = 2 // 2 seconds
		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(-3 * time.Second), Code: http.StatusOK,
		})
	})

	t.Run("IssueAt-After_now-Add_skew--Valid_jwt", func(t *testing.T) {
		spec.JWTIssuedAtValidationSkew = 1

		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(+time.Second), Code: http.StatusOK,
		})
	})
}

func TestJWTSessionNotBeforeValidationConfigs(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	pID := CreatePolicy()
	jwtAuthHeaderGen := func(skew time.Duration) map[string]string {
		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)["policy_id"] = pID
			t.Claims.(jwt.MapClaims)["user_id"] = "user123"
			t.Claims.(jwt.MapClaims)["nbf"] = time.Now().Add(skew).Unix()
		})
		return map[string]string{"authorization": jwtToken}
	}

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.Proxy.ListenPath = "/"
		spec.JWTSigningMethod = "rsa"
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
	})[0]

	// This test is successful by definition
	t.Run("NotBefore_Before_now-Valid_jwt", func(t *testing.T) {
		spec.JWTNotBeforeValidationSkew = 0

		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(-time.Second), Code: http.StatusOK,
		})
	})

	t.Run("NotBefore_After_now--Invalid_jwt", func(t *testing.T) {
		spec.JWTNotBeforeValidationSkew = 0 //Default value

		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers:   jwtAuthHeaderGen(+time.Second),
			Code:      http.StatusUnauthorized,
			BodyMatch: "Key not authorized: token is not valid yet",
		})
	})

	t.Run("NotBefore_After_now-Add_skew--valid_jwt", func(t *testing.T) {
		spec.JWTNotBeforeValidationSkew = 1

		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(+time.Second), Code: http.StatusOK,
		})
	})

	t.Run("NotBefore_After_now-Huge_skew--valid_jwt", func(t *testing.T) {
		spec.JWTNotBeforeValidationSkew = 1000 // This value is so high that it's actually similar to disabling the claim.

		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: jwtAuthHeaderGen(+time.Second), Code: http.StatusOK,
		})
	})
}

func TestJWTExistingSessionRSAWithRawSourceInvalidPolicyID(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})[0]

	LoadAPI(spec)

	p1ID := CreatePolicy()
	user_id := uuid.New()

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = user_id
		t.Claims.(jwt.MapClaims)["policy_id"] = p1ID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Initial request with valid policy", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})

	// put in JWT invalid policy ID and do request again
	jwtTokenInvalidPolicy := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = user_id
		t.Claims.(jwt.MapClaims)["policy_id"] = "abcdef"
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders = map[string]string{"authorization": jwtTokenInvalidPolicy}
	t.Run("Request with invalid policy in JWT", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			BodyMatch: "key not authorized: no matching policy",
			Code:      http.StatusForbidden,
		})
	})
}

func TestJWTScopeToPolicyMapping(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	basePolicyID := CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			"base-api": {
				Limit: &user.APILimit{
					Rate:     111,
					Per:      3600,
					QuotaMax: -1,
				},
			},
		}
		p.Partitions = user.PolicyPartitions{
			PerAPI: true,
		}
	})

	spec1 := BuildAPI(func(spec *APISpec) {
		spec.APIID = "api1"
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/api1"
		spec.OrgID = "default"
	})[0]

	p1ID := CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			spec1.APIID: {
				Limit: &user.APILimit{
					Rate:     100,
					Per:      60,
					QuotaMax: -1,
				},
			},
		}
		p.Partitions = user.PolicyPartitions{
			PerAPI: true,
		}
	})

	spec2 := BuildAPI(func(spec *APISpec) {
		spec.APIID = "api2"
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/api2"
		spec.OrgID = "default"
	})[0]

	p2ID := CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			spec2.APIID: {
				Limit: &user.APILimit{
					Rate:     500,
					Per:      30,
					QuotaMax: -1,
				},
			},
		}
		p.Partitions = user.PolicyPartitions{
			PerAPI: true,
		}
	})

	spec3 := BuildAPI(func(spec *APISpec) {
		spec.APIID = "api3"
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/api3"
		spec.OrgID = "default"
	})[0]

	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "base-api"
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/base"
		spec.JWTScopeToPolicyMapping = map[string]string{
			"user:read":  p1ID,
			"user:write": p2ID,
		}
		spec.OrgID = "default"
	})[0]

	LoadAPI(spec, spec1, spec2, spec3)

	userID := "user-" + uuid.New()

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = userID
		t.Claims.(jwt.MapClaims)["policy_id"] = basePolicyID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
		t.Claims.(jwt.MapClaims)["scope"] = "user:read user:write"
	})

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with scope in JWT to create a key session", func(t *testing.T) {
		ts.Run(t,
			test.TestCase{
				Headers: authHeaders,
				Path:    "/base",
				Code:    http.StatusOK,
			})
	})

	// check that key has right set of policies assigned - there should be all three - base one and two from scope
	sessionID := generateToken("default", fmt.Sprintf("%x", md5.Sum([]byte(userID))))
	t.Run("Request to check that session has got correct apply_policies value", func(t *testing.T) {
		ts.Run(
			t,
			test.TestCase{
				Method:    http.MethodGet,
				Path:      "/tyk/keys/" + sessionID,
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatchFunc: func(body []byte) bool {
					expectedResp := map[interface{}]bool{
						basePolicyID: true,
						p1ID:         true,
						p2ID:         true,
					}

					resp := map[string]interface{}{}
					json.Unmarshal(body, &resp)
					realResp := map[interface{}]bool{}
					for _, val := range resp["apply_policies"].([]interface{}) {
						realResp[val] = true
					}

					return reflect.DeepEqual(realResp, expectedResp)
				},
			},
		)
	})

	// try to access api1 using JWT issued via base-api
	t.Run("Request to api1", func(t *testing.T) {
		ts.Run(
			t,
			test.TestCase{
				Headers: authHeaders,
				Method:  http.MethodGet,
				Path:    "/api1",
				Code:    http.StatusOK,
			},
		)
	})

	// try to access api2 using JWT issued via base-api
	t.Run("Request to api2", func(t *testing.T) {
		ts.Run(
			t,
			test.TestCase{
				Headers: authHeaders,
				Method:  http.MethodGet,
				Path:    "/api2",
				Code:    http.StatusOK,
			},
		)
	})

	// try to access api3 (which is not granted via base policy nor scope-policy mapping) using JWT issued via base-api
	t.Run("Request to api3", func(t *testing.T) {
		ts.Run(
			t,
			test.TestCase{
				Headers: authHeaders,
				Method:  http.MethodGet,
				Path:    "/api3",
				Code:    http.StatusForbidden,
			},
		)
	})

	// try to change scope to policy mapping and request using existing session
	p3ID := CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			spec3.APIID: {
				Limit: &user.APILimit{
					Rate:     500,
					Per:      30,
					QuotaMax: -1,
				},
			},
		}
		p.Partitions = user.PolicyPartitions{
			PerAPI: true,
		}
	})

	spec.JWTScopeToPolicyMapping = map[string]string{
		"user:read": p3ID,
	}

	LoadAPI(spec)

	t.Run("Request with changed scope in JWT and key with existing session", func(t *testing.T) {
		ts.Run(t,
			test.TestCase{
				Headers: authHeaders,
				Path:    "/base",
				Code:    http.StatusOK,
			})
	})

	// check that key has right set of policies assigned - there should be updated list (base one and one from scope)
	t.Run("Request to check that session has got changed apply_policies value", func(t *testing.T) {
		ts.Run(
			t,
			test.TestCase{
				Method:    http.MethodGet,
				Path:      "/tyk/keys/" + sessionID,
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatchFunc: func(body []byte) bool {
					expectedResp := map[interface{}]bool{
						basePolicyID: true,
						p3ID:         true,
					}

					resp := map[string]interface{}{}
					json.Unmarshal(body, &resp)
					realResp := map[interface{}]bool{}
					for _, val := range resp["apply_policies"].([]interface{}) {
						realResp[val] = true
					}

					return reflect.DeepEqual(realResp, expectedResp)
				},
			},
		)
	})

}

func TestJWTExistingSessionRSAWithRawSourcePolicyIDChanged(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
		spec.OrgID = "default"
	})[0]

	LoadAPI(spec)

	p1ID := CreatePolicy(func(p *user.Policy) {
		p.QuotaMax = 111
	})
	p2ID := CreatePolicy(func(p *user.Policy) {
		p.QuotaMax = 999
	})
	user_id := uuid.New()

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = user_id
		t.Claims.(jwt.MapClaims)["policy_id"] = p1ID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	sessionID := generateToken("default", fmt.Sprintf("%x", md5.Sum([]byte(user_id))))

	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Initial request with 1st policy", func(t *testing.T) {
		ts.Run(
			t,
			test.TestCase{
				Headers: authHeaders, Code: http.StatusOK,
			},
			test.TestCase{
				Method:    http.MethodGet,
				Path:      "/tyk/keys/" + sessionID,
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatch: `"quota_max":111`,
			},
		)
	})

	// check key/session quota

	// put in JWT another valid policy ID and do request again
	jwtTokenAnotherPolicy := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = user_id
		t.Claims.(jwt.MapClaims)["policy_id"] = p2ID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders = map[string]string{"authorization": jwtTokenAnotherPolicy}
	t.Run("Request with new valid policy in JWT", func(t *testing.T) {
		ts.Run(t,
			test.TestCase{
				Headers: authHeaders, Code: http.StatusOK,
			},
			test.TestCase{
				Method:    http.MethodGet,
				Path:      "/tyk/keys/" + sessionID,
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatch: `"quota_max":999`,
			},
		)
	})
}

// JWTSessionRSAWithJWK

func prepareJWTSessionRSAWithJWK() string {
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = testHttpJWK
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})

	pID := CreatePolicy()
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	return jwtToken
}

func TestJWTSessionRSAWithJWK(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithJWK()
	authHeaders := map[string]string{"authorization": jwtToken}

	t.Run("JWTSessionRSAWithJWK", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func BenchmarkJWTSessionRSAWithJWK(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	jwtToken := prepareJWTSessionRSAWithJWK()
	authHeaders := map[string]string{"authorization": jwtToken}

	for i := 0; i < b.N; i++ {
		ts.Run(
			b,
			test.TestCase{
				Headers: authHeaders,
				Code:    http.StatusOK,
			},
		)
	}
}

// JWTSessionRSAWithEncodedJWK

func prepareJWTSessionRSAWithEncodedJWK() (*APISpec, string) {
	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})[0]

	pID := CreatePolicy()
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
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
	ts := StartTest()
	defer ts.Close()

	spec, jwtToken := prepareJWTSessionRSAWithEncodedJWK()

	authHeaders := map[string]string{"authorization": jwtToken}

	t.Run("Direct JWK URL", func(t *testing.T) {
		spec.JWTSource = testHttpJWK
		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})

	t.Run("Base64 JWK URL", func(t *testing.T) {
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(testHttpJWK))
		LoadAPI(spec)

		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func BenchmarkJWTSessionRSAWithEncodedJWK(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	spec, jwtToken := prepareJWTSessionRSAWithEncodedJWK()
	spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(testHttpJWK))

	LoadAPI(spec)

	authHeaders := map[string]string{"authorization": jwtToken}

	for i := 0; i < b.N; i++ {
		ts.Run(
			b,
			test.TestCase{
				Headers: authHeaders,
				Code:    http.StatusOK,
			},
		)
	}
}

func TestJWTHMACIdNewClaim(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//If we skip the check then the Id will be taken from SUB and the call will succeed
	_, jwtToken := prepareGenericJWTSession(t.Name(), HMACSign, "user-id", true)
	defer ResetTestConfig()
	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/HMAC signature/id in user-id claim", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func TestJWTRSAIdInClaimsWithBaseField(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})

	pID := CreatePolicy()

	//First test - user id in the configured base field 'user_id'
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user123@test.com"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})
	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/RSA signature/user id in user_id claim", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})

	//user-id claim configured but it's empty - returning an error
	jwtToken = CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = ""
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})
	authHeaders = map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/RSA signature/empty user_id claim", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: "found an empty user ID in predefined base field claim user_id",
		})
	})

	//user-id claim configured but not found fallback to sub
	jwtToken = CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["sub"] = "user123@test.com"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})
	authHeaders = map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/RSA signature/user id in sub claim", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})

	//user-id claim not found fallback to sub that is empty
	jwtToken = CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["sub"] = ""
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})
	authHeaders = map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/RSA signature/empty sub claim", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: "found an empty user ID in sub claim",
		})
	})

	//user-id and sub claims not found
	jwtToken = CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})
	authHeaders = map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/RSA signature/no base field or sub claims", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: "no suitable claims for user ID were found",
		})
	})
}

func TestJWTRSAIdInClaimsWithoutBaseField(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = ""
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})

	pID := CreatePolicy()

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["sub"] = "user123@test.com" //is ignored
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})
	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/RSA signature/id found in default sub", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})

	//Id is not found since there's no sub claim and user_id has't been set in the api def (spec.JWTIdentityBaseField)
	jwtToken = CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["user_id"] = "user123@test.com" //is ignored
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})
	authHeaders = map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/RSA signature/no id claims", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: "no suitable claims for user ID were found",
		})
	})
}

func TestJWTDefaultPolicies(t *testing.T) {
	const apiID = "testapid"
	const identitySource = "user_id"
	const policyFieldName = "policy_id"

	ts := StartTest()
	defer ts.Close()

	defPol1 := CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			apiID: {},
		}
		p.Partitions = user.PolicyPartitions{
			Quota: true,
		}
	})

	defPol2 := CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			apiID: {},
		}
		p.Partitions = user.PolicyPartitions{
			RateLimit: true,
		}
	})

	tokenPol := CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			apiID: {},
		}
		p.Partitions = user.PolicyPartitions{
			Acl: true,
		}
	})

	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = identitySource
		spec.JWTDefaultPolicies = []string{
			defPol1,
			defPol2,
		}
		spec.Proxy.ListenPath = "/"
	})[0]

	data := []byte("dummy")
	keyID := fmt.Sprintf("%x", md5.Sum(data))
	sessionID := generateToken(spec.OrgID, keyID)

	assert := func(t *testing.T, expected []string) {
		session, _ := FallbackKeySesionManager.SessionDetail(sessionID, false)
		actual := session.PolicyIDs()
		if !reflect.DeepEqual(expected, actual) {
			t.Fatalf("Expected %v, actaul %v", expected, actual)
		}
	}

	t.Run("Policy field name empty", func(t *testing.T) {
		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)[identitySource] = "dummy"
			t.Claims.(jwt.MapClaims)[policyFieldName] = tokenPol
		})

		authHeaders := map[string]string{"authorization": jwtToken}

		// Default
		LoadAPI(spec)
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{defPol1, defPol2})

		// Same to check stored correctly
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{defPol1, defPol2})

		// Remove one of default policies
		spec.JWTDefaultPolicies = []string{defPol1}
		LoadAPI(spec)
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{defPol1})

		// Add a default policy
		spec.JWTDefaultPolicies = []string{defPol1, defPol2}
		LoadAPI(spec)
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{defPol1, defPol2})
	})

	t.Run("Policy field name nonempty but empty claim", func(t *testing.T) {
		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)[identitySource] = "dummy"
			t.Claims.(jwt.MapClaims)[policyFieldName] = ""
		})

		authHeaders := map[string]string{"authorization": jwtToken}

		// Default
		LoadAPI(spec)
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{defPol1, defPol2})

		// Same to check stored correctly
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{defPol1, defPol2})

		// Remove one of default policies
		spec.JWTDefaultPolicies = []string{defPol1}
		LoadAPI(spec)
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{defPol1})

		// Add a default policy
		spec.JWTDefaultPolicies = []string{defPol1, defPol2}
		LoadAPI(spec)
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{defPol1, defPol2})
	})

	t.Run("Policy field name nonempty invalid policy ID in claim", func(t *testing.T) {
		spec.JWTPolicyFieldName = policyFieldName
		LoadAPI(spec)

		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)[identitySource] = "dummy"
			t.Claims.(jwt.MapClaims)[policyFieldName] = "invalid"
		})

		authHeaders := map[string]string{"authorization": jwtToken}

		_, _ = ts.Run(t, []test.TestCase{
			{Headers: authHeaders, Code: http.StatusForbidden},
			{Headers: authHeaders, Code: http.StatusForbidden},
		}...)

		// Reset
		spec.JWTPolicyFieldName = ""
	})

	t.Run("Default to Claim transition", func(t *testing.T) {
		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)[identitySource] = "dummy"
			t.Claims.(jwt.MapClaims)[policyFieldName] = tokenPol
		})

		authHeaders := map[string]string{"authorization": jwtToken}

		// Default
		LoadAPI(spec)
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{defPol1, defPol2})

		// Same to check stored correctly
		LoadAPI(spec)
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{defPol1, defPol2})

		// Claim
		spec.JWTPolicyFieldName = policyFieldName
		LoadAPI(spec)
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{tokenPol})
	})

	t.Run("Claim to Default transition", func(t *testing.T) {
		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)[identitySource] = "dummy"
			t.Claims.(jwt.MapClaims)[policyFieldName] = tokenPol
		})

		authHeaders := map[string]string{"authorization": jwtToken}

		// Claim
		spec.JWTPolicyFieldName = policyFieldName
		LoadAPI(spec)
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{tokenPol})

		// Same to check stored correctly
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{tokenPol})

		// Default
		spec.JWTPolicyFieldName = ""
		LoadAPI(spec)
		_, _ = ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
		assert(t, []string{defPol1, defPol2})
	})
}

func TestJWTECDSASign(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//If we skip the check then the Id will be taken from SUB and the call will succeed
	_, jwtToken := prepareGenericJWTSession(t.Name(), ECDSASign, KID, false)
	defer ResetTestConfig()
	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/ECDSA signature needs a test. currently defaults to HMAC", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func TestJWTUnknownSign(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	//If we skip the check then the Id will be taken from SUB and the call will succeed
	_, jwtToken := prepareGenericJWTSession(t.Name(), "bla", KID, false)
	defer ResetTestConfig()
	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/ECDSA signature needs a test. currently defaults to HMAC", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers: authHeaders, Code: http.StatusOK,
		})
	})
}

func TestJWTRSAInvalidPublickKey(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKeyinvalid))
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})

	pID := CreatePolicy()

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Header["kid"] = "12345"
		t.Claims.(jwt.MapClaims)["foo"] = "bar"
		t.Claims.(jwt.MapClaims)["sub"] = "user123@test.com" //is ignored
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})
	authHeaders := map[string]string{"authorization": jwtToken}
	t.Run("Request with valid JWT/RSA signature/invalid public key", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Headers:   authHeaders,
			Code:      http.StatusForbidden,
			BodyMatch: "Key not authorized:Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key",
		})
	})
}

func createExpiringPolicy(pGen ...func(p *user.Policy)) string {
	pID := keyGen.GenerateAuthKey("")
	pol := CreateStandardPolicy()
	pol.ID = pID
	pol.KeyExpiresIn = 1

	if len(pGen) > 0 {
		pGen[0](pol)
	}

	policiesMu.Lock()
	policiesByID[pID] = *pol
	policiesMu.Unlock()

	return pID
}

func TestJWTExpOverride(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/"
	})

	t.Run("JWT expiration bigger then policy", func(t *testing.T) {
		//create policy which sets keys to have expiry in one second
		pID := CreatePolicy(func(p *user.Policy) {
			p.KeyExpiresIn = 1
		})

		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)["sub"] = uuid.New()
			t.Claims.(jwt.MapClaims)["policy_id"] = pID
			t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Second * 72).Unix()
		})

		authHeaders := map[string]string{"authorization": jwtToken}

		//JWT expiry overrides internal token which gets expiry from policy so second request will pass
		ts.Run(t, []test.TestCase{
			{Headers: authHeaders, Code: http.StatusOK, Delay: 1100 * time.Millisecond},
			{Headers: authHeaders, Code: http.StatusOK},
		}...)
	})

	t.Run("JWT expiration smaller then policy", func(t *testing.T) {
		pID := CreatePolicy(func(p *user.Policy) {
			p.KeyExpiresIn = 5
		})

		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)["sub"] = uuid.New()
			t.Claims.(jwt.MapClaims)["policy_id"] = pID
			t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(-time.Second).Unix()
		})

		authHeaders := map[string]string{"authorization": jwtToken}

		// Should not allow expired JWTs
		ts.Run(t, []test.TestCase{
			{Headers: authHeaders, Code: http.StatusUnauthorized},
		}...)
	})

	t.Run("JWT expired but renewed, policy without expiration", func(t *testing.T) {
		pID := CreatePolicy(func(p *user.Policy) {
			p.KeyExpiresIn = 0
		})

		userID := uuid.New()

		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)["sub"] = userID
			t.Claims.(jwt.MapClaims)["policy_id"] = pID
			t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Second).Unix()
		})

		newJwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Claims.(jwt.MapClaims)["sub"] = userID
			t.Claims.(jwt.MapClaims)["policy_id"] = pID
			t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(5 * time.Second).Unix()
		})

		authHeaders := map[string]string{"authorization": jwtToken}
		newAuthHeaders := map[string]string{"authorization": newJwtToken}

		// Should not allow expired JWTs
		ts.Run(t, []test.TestCase{
			{Headers: authHeaders, Code: http.StatusOK, Delay: 1100 * time.Millisecond},
			{Headers: authHeaders, Code: http.StatusUnauthorized},
			{Headers: newAuthHeaders, Code: http.StatusOK},
		}...)
	})

}
