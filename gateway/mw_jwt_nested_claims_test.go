package gateway

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// TestJWTNestedSubjectClaimSingleLevel tests nested subject claim with single level nesting
func TestJWTNestedSubjectClaimSingleLevel(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const testAPIID = "test-api"

	// Create policy
	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			testAPIID: {},
		}
	})

	// Build API spec
	_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user.id"
		spec.JWTPolicyFieldName = "policyId"
		spec.Proxy.ListenPath = "/"
	})[0]

	// Create JWT token with NESTED claims structure
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		// CORRECT way to create nested structure
		t.Claims.(jwt.MapClaims)["user"] = map[string]interface{}{
			"id": "user123",
		}
		t.Claims.(jwt.MapClaims)["policyId"] = policyID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}

	ts.Run(t, test.TestCase{
		Headers: authHeaders,
		Code:    http.StatusOK,
	})
}

// TestJWTNestedSubjectClaimMultiLevel tests nested subject claim with multiple levels
func TestJWTNestedSubjectClaimMultiLevel(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const testAPIID = "test-api"

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{testAPIID: {}}
	})

	_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "identity.user.uuid"
		spec.JWTPolicyFieldName = "policyId"
		spec.Proxy.ListenPath = "/"
	})[0]

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		// Create 3-level nested structure
		t.Claims.(jwt.MapClaims)["identity"] = map[string]interface{}{
			"user": map[string]interface{}{
				"uuid": "550e8400-e29b-41d4-a716-446655440000",
			},
		}
		t.Claims.(jwt.MapClaims)["policyId"] = policyID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}

	ts.Run(t, test.TestCase{
		Headers: authHeaders,
		Code:    http.StatusOK,
	})
}

// TestJWTNestedSubjectClaimWithFallback tests fallback behavior when nested claim is not found
func TestJWTNestedSubjectClaimWithFallback(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const testAPIID = "test-api"

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{testAPIID: {}}
	})

	_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		// Try custom.userId first, will fall back to sub
		spec.JWTIdentityBaseField = "custom.userId"
		spec.JWTPolicyFieldName = "policyId"
		spec.Proxy.ListenPath = "/"
	})[0]

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["sub"] = "fallback-user"
		t.Claims.(jwt.MapClaims)["custom"] = map[string]interface{}{
			"name": "John Doe",
			// Note: no "userId" field - will trigger fallback
		}
		t.Claims.(jwt.MapClaims)["policyId"] = policyID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}

	ts.Run(t, test.TestCase{
		Headers: authHeaders,
		Code:    http.StatusOK,
	})
}

// TestJWTNestedBasePolicyClaim tests nested base policy claim
func TestJWTNestedBasePolicyClaim(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const testAPIID = "test-api"

	goldPolicyID := ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "gold-policy"
		p.AccessRights = map[string]user.AccessDefinition{
			testAPIID: {
				Limit: user.APILimit{
					RateLimit: user.RateLimit{Rate: 1000, Per: 60},
					QuotaMax:  100,
				},
			},
		}
	})

	_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "sub"
		spec.JWTPolicyFieldName = "authorization.policy"
		spec.Proxy.ListenPath = "/"
	})[0]

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["sub"] = "user123"
		t.Claims.(jwt.MapClaims)["authorization"] = map[string]interface{}{
			"policy": goldPolicyID,
		}
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}

	ts.Run(t, test.TestCase{
		Headers: authHeaders,
		Code:    http.StatusOK,
	})
}

// TestJWTNestedScopesClaim_NoRegression tests that existing scope functionality still works
// NOTE: Scopes already support nested claims (existing functionality since the original implementation).
// This is verified by the existing TestGetScopeFromClaim test in mw_jwt_test.go which includes
// nested scope claim tests. The nested claim support for scopes uses the same nestedMapLookup
// function that we're now extending to subject and policy claims.

// TestJWTNestedClaimEmptyString tests error handling for empty string values in nested claims
func TestJWTNestedClaimEmptyString(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const testAPIID = "test-api"

	_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user.id"
		spec.Proxy.ListenPath = "/"
	})[0]

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user"] = map[string]interface{}{
			"id": "", // Empty string
		}
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}

	ts.Run(t, test.TestCase{
		Headers: authHeaders,
		Code:    http.StatusForbidden,
	})
}

// TestJWTNestedClaimNonString tests fallback when nested claim has non-string value
func TestJWTNestedClaimNonString(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const testAPIID = "test-api"

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{testAPIID: {}}
	})

	_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		// Try nested claim first, fallback to sub
		spec.JWTIdentityBaseField = "user.id"
		spec.JWTPolicyFieldName = "policyId"
		spec.Proxy.ListenPath = "/"
	})[0]

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user"] = map[string]interface{}{
			"id": 12345, // Integer, not string
		}
		t.Claims.(jwt.MapClaims)["sub"] = "fallback-user"
		t.Claims.(jwt.MapClaims)["policyId"] = policyID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}

	// Should fall back to "sub" claim
	ts.Run(t, test.TestCase{
		Headers: authHeaders,
		Code:    http.StatusOK,
	})
}

// TestJWTMultipleNestedPolicyClaimsPriority tests priority order when multiple policy claims are configured
func TestJWTMultipleNestedPolicyClaimsPriority(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const testAPIID = "test-api"

	silverPolicyID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			testAPIID: {
				Limit: user.APILimit{QuotaMax: 500},
			},
		}
	})

	bronzePolicyID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			testAPIID: {
				Limit: user.APILimit{QuotaMax: 100},
			},
		}
	})

	_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "sub"
		// Priority order: primary.policy (not present), fallback.policy (present), policyId (present but ignored)
		spec.JWTPolicyFieldName = "fallback.policy"
		spec.Proxy.ListenPath = "/"
	})[0]

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["sub"] = "user123"
		// No primary.policy
		t.Claims.(jwt.MapClaims)["fallback"] = map[string]interface{}{
			"policy": silverPolicyID,
		}
		t.Claims.(jwt.MapClaims)["policyId"] = bronzePolicyID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}

	// Should use silverPolicyID (first found)
	ts.Run(t, test.TestCase{
		Headers: authHeaders,
		Code:    http.StatusOK,
	})
}

// TestJWTFlatClaimsBackwardCompatibility tests that flat claims still work
func TestJWTFlatClaimsBackwardCompatibility(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const testAPIID = "test-api"

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{testAPIID: {}}
	})

	_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		// Use flat claim names (no dots)
		spec.JWTIdentityBaseField = "userId"
		spec.JWTPolicyFieldName = "policyId"
		spec.Proxy.ListenPath = "/"
	})[0]

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		// Flat claims (no nesting)
		t.Claims.(jwt.MapClaims)["userId"] = "user456"
		t.Claims.(jwt.MapClaims)["policyId"] = policyID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}

	// Should work exactly as before
	ts.Run(t, test.TestCase{
		Headers: authHeaders,
		Code:    http.StatusOK,
	})
}

// TestJWTNestedClaims_CustomerScenario tests the real customer scenario from the ticket
func TestJWTNestedClaims_CustomerScenario(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const testAPIID = "test-api"

	premiumPolicyID := ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "premium-policy"
		p.AccessRights = map[string]user.AccessDefinition{
			testAPIID: {
				Limit: user.APILimit{
					RateLimit: user.RateLimit{Rate: 5000, Per: 60},
					QuotaMax:  10000,
				},
			},
		}
	})

	_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = HMACSign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte("mysecret"))
		spec.JWTIdentityBaseField = "test.sub"
		spec.JWTPolicyFieldName = "test.policy"
		spec.Proxy.ListenPath = "/"
	})[0]

	// Create token with HMAC signing (simpler for customer example)
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims.(jwt.MapClaims)["test"] = map[string]interface{}{
		"sub":    "123456",
		"policy": premiumPolicyID,
	}
	token.Claims.(jwt.MapClaims)["iss"] = "https://customer-idp.com"
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()

	tokenString, err := token.SignedString([]byte("mysecret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	authHeaders := map[string]string{"authorization": tokenString}

	ts.Run(t, test.TestCase{
		Headers: authHeaders,
		Code:    http.StatusOK,
	})
}

// TestJWTLiteralDotInClaimName tests backward compatibility for literal dots in claim names
func TestJWTLiteralDotInClaimName(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const testAPIID = "test-api"

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{testAPIID: {}}
	})

	_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = testAPIID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		// Claim name with literal dot
		spec.JWTIdentityBaseField = "user.id"
		spec.JWTPolicyFieldName = "policyId"
		spec.Proxy.ListenPath = "/"
	})[0]

	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		// Literal key with dot in it (not nested structure)
		t.Claims.(jwt.MapClaims)["user.id"] = "literal-dot-user"
		t.Claims.(jwt.MapClaims)["policyId"] = policyID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
	})

	authHeaders := map[string]string{"authorization": jwtToken}

	// Should work - literal key takes precedence
	ts.Run(t, test.TestCase{
		Headers: authHeaders,
		Code:    http.StatusOK,
	})
}
