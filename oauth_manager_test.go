package main

/*
	NOTE: Requires the test tyk.conf to be in place and the settings to b correct - ugly, I know, but necessary for the end to end to work correctly.
*/

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"fmt"

	"net/http"

	"time"

	"github.com/satori/go.uuid"

	"github.com/lonelycode/osin"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

const (
	authRedirectUri  = "http://client.oauth.com"
	authRedirectUri2 = "http://client2.oauth.com"
	authClientID     = "1234"
	authClientSecret = "aabbccdd"
)

const keyRules = `{
	"last_check": 1402492859,
	"org_id": "53ac07777cbb8c2d53000002",
	"rate": 1,
	"per": 1,
	"quota_max": -1,
	"quota_renews": 1399567002,
	"quota_remaining": 10,
	"quota_renewal_rate": 300
}`

func buildTestOAuthSpec(apiGens ...func(spec *APISpec)) *APISpec {
	return buildAPI(func(spec *APISpec) {
		spec.APIID = "999999"
		spec.OrgID = "default"
		spec.Auth = apidef.Auth{
			AuthHeaderName: "authorization",
		}
		spec.UseKeylessAccess = false
		spec.UseOauth2 = true
		spec.Oauth2Meta = struct {
			AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types"`
			AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types"`
			AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect"`
		}{
			AllowedAccessTypes: []osin.AccessRequestType{
				"authorization_code",
				"refresh_token",
				"client_credentials",
			},
			AllowedAuthorizeTypes: []osin.AuthorizeRequestType{
				"code",
				"token",
			},
			AuthorizeLoginRedirect: testHttpPost,
		}
		spec.NotificationsDetails = apidef.NotificationsManager{
			SharedSecret:      "9878767657654343123434556564444",
			OAuthKeyChangeURL: testHttpPost,
		}
		spec.VersionData = struct {
			NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
			DefaultVersion string                        `bson:"default_version" json:"default_version"`
			Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
		}{
			NotVersioned: true,
			Versions: map[string]apidef.VersionInfo{
				"v1": {
					Name: "v1",
				},
			},
		}
		spec.Proxy.ListenPath = "/APIID/"
		spec.Proxy.StripListenPath = true

		if len(apiGens) > 0 {
			apiGens[0](spec)
		}
	})[0]
}

func loadTestOAuthSpec() *APISpec {
	return loadAPI(buildTestOAuthSpec())[0]
}

func createTestOAuthClient(spec *APISpec, clientID string) {
	pID := createPolicy(func(p *user.Policy) {
		p.ID = "TEST-4321"
		p.AccessRights = map[string]user.AccessDefinition{
			"test": {
				APIID: "test",
			},
			"abc": {
				APIID: "abc",
			},
		}
	})

	var redirectURI string
	// If separator is not set that means multiple redirect uris not supported
	if config.Global().OauthRedirectUriSeparator == "" {
		redirectURI = "http://client.oauth.com"

		// If separator config is set that means multiple redirect uris are supported
	} else {
		redirectURI = strings.Join([]string{"http://client.oauth.com", "http://client2.oauth.com", "http://client3.oauth.com"}, config.Global().OauthRedirectUriSeparator)
	}
	testClient := OAuthClient{
		ClientID:          clientID,
		ClientSecret:      authClientSecret,
		ClientRedirectURI: redirectURI,
		PolicyID:          pID,
	}
	spec.OAuthManager.OsinServer.Storage.SetClient(testClient.ClientID, &testClient, false)
}

func TestOauthMultipleAPIs(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := buildTestOAuthSpec(func(spec *APISpec) {
		spec.APIID = "oauth2"
		spec.UseOauth2 = true
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/api1/"
	})
	spec2 := buildTestOAuthSpec(func(spec *APISpec) {
		spec.APIID = "oauth2_copy"
		spec.UseKeylessAccess = false
		spec.UseOauth2 = true
		spec.Proxy.ListenPath = "/api2/"
	})

	apis := loadAPI(spec, spec2)
	spec = apis[0]
	spec2 = apis[1]

	pID := createPolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			"oauth2": {
				APIID: "oauth2",
			},
			"oauth2_copy": {
				APIID: "oauth2_copy",
			},
		}
	})

	testClient := OAuthClient{
		ClientID:          authClientID,
		ClientSecret:      authClientSecret,
		ClientRedirectURI: authRedirectUri,
		PolicyID:          pID,
	}
	spec.OAuthManager.OsinServer.Storage.SetClient(testClient.ClientID, &testClient, false)
	spec2.OAuthManager.OsinServer.Storage.SetClient(testClient.ClientID, &testClient, false)

	param := make(url.Values)
	param.Set("response_type", "token")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	param.Set("key_rules", keyRules)

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}

	var err error
	resp, err := ts.Run(t, test.TestCase{
		Path:      "/api1/tyk/oauth/authorize-client/",
		AdminAuth: true,
		Data:      param.Encode(),
		Headers:   headers,
		Method:    http.MethodPost,
		Code:      http.StatusOK,
		BodyMatch: `"access_token"`,
	})
	if err != nil {
		t.Fatal(err)
	}

	token := tokenData{}
	json.NewDecoder(resp.Body).Decode(&token)
	authHeader := map[string]string{
		"Authorization": "Bearer " + token.AccessToken,
	}

	ts.Run(t,
		test.TestCase{
			Path:    "/api1/get",
			Headers: authHeader,
			Method:  http.MethodGet,
			Code:    http.StatusOK,
		},
		test.TestCase{
			Path:    "/api2/get",
			Headers: authHeader,
			Method:  http.MethodGet,
			Code:    http.StatusOK,
		},
	)
}

func TestAuthCodeRedirect(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	t.Run("Authorize request with redirect", func(t *testing.T) {
		param := make(url.Values)
		param.Set("response_type", "code")
		param.Set("redirect_uri", authRedirectUri)
		param.Set("client_id", authClientID)

		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		ts.Run(t, test.TestCase{
			Path:    "/APIID/oauth/authorize/",
			Data:    param.Encode(),
			Headers: headers,
			Method:  http.MethodPost,
			Code:    http.StatusTemporaryRedirect,
		})
	})
}

func TestAuthCodeRedirectMultipleURL(t *testing.T) {
	// Enable multiple Redirect URIs
	globalConf := config.Global()
	globalConf.OauthRedirectUriSeparator = ","
	config.SetGlobal(globalConf)
	defer resetTestConfig()

	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	t.Run("Client authorize request with multiple redirect URI", func(t *testing.T) {
		param := make(url.Values)
		param.Set("response_type", "code")
		param.Set("redirect_uri", authRedirectUri2)
		param.Set("client_id", authClientID)

		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		ts.Run(t, test.TestCase{
			Path:    "/APIID/oauth/authorize/",
			Data:    param.Encode(),
			Headers: headers,
			Method:  http.MethodPost,
			Code:    http.StatusTemporaryRedirect,
		})
	})
}

func TestAuthCodeRedirectInvalidMultipleURL(t *testing.T) {
	// Disable multiple Redirect URIs
	globalConf := config.Global()
	globalConf.OauthRedirectUriSeparator = ""
	config.SetGlobal(globalConf)
	defer resetTestConfig()

	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	t.Run("Client authorize request with invalid redirect URI", func(t *testing.T) {
		param := make(url.Values)
		param.Set("response_type", "code")
		param.Set("redirect_uri", authRedirectUri2)
		param.Set("client_id", authClientID)

		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		ts.Run(t, test.TestCase{
			Path:    "/APIID/oauth/authorize/",
			Data:    param.Encode(),
			Headers: headers,
			Method:  http.MethodPost,
			Code:    http.StatusForbidden,
		})
	})
}

func TestAPIClientAuthorizeAuthCode(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	t.Run("Client authorize code request", func(t *testing.T) {
		param := make(url.Values)
		param.Set("response_type", "code")
		param.Set("redirect_uri", authRedirectUri)
		param.Set("client_id", authClientID)
		param.Set("key_rules", keyRules)

		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		ts.Run(t, test.TestCase{
			Path:      "/APIID/tyk/oauth/authorize-client/",
			AdminAuth: true,
			Data:      param.Encode(),
			Headers:   headers,
			Method:    http.MethodPost,
			Code:      http.StatusOK,
			BodyMatch: `"code"`,
		})
	})
}

func TestAPIClientAuthorizeToken(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	t.Run("Client authorize token request", func(t *testing.T) {
		param := make(url.Values)
		param.Set("response_type", "token")
		param.Set("redirect_uri", authRedirectUri)
		param.Set("client_id", authClientID)
		param.Set("key_rules", keyRules)

		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		ts.Run(t, test.TestCase{
			Path:      "/APIID/tyk/oauth/authorize-client/",
			AdminAuth: true,
			Data:      param.Encode(),
			Headers:   headers,
			Method:    http.MethodPost,
			Code:      http.StatusOK,
			BodyMatch: `"access_token"`,
		})
	})
}

func TestDeleteOauthClient(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	var resp *http.Response

	t.Run("Client authorize token request", func(t *testing.T) {
		param := make(url.Values)
		param.Set("response_type", "token")
		param.Set("redirect_uri", authRedirectUri)
		param.Set("client_id", authClientID)
		param.Set("key_rules", keyRules)

		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		var err error
		resp, err = ts.Run(t, test.TestCase{
			Path:      "/APIID/tyk/oauth/authorize-client/",
			AdminAuth: true,
			Data:      param.Encode(),
			Headers:   headers,
			Method:    http.MethodPost,
			Code:      http.StatusOK,
			BodyMatch: `"access_token"`,
		})
		if err != nil {
			t.Error(err)
		}
	})

	token := tokenData{}
	json.NewDecoder(resp.Body).Decode(&token)
	authHeader := map[string]string{
		"Authorization": "Bearer " + token.AccessToken,
	}
	t.Run("Make request to API with supplying token", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Path:    "/APIID/get",
			Headers: authHeader,
			Method:  http.MethodGet,
			Code:    http.StatusOK,
		})
	})

	t.Run("Delete OAuth-client and check that it is gone", func(t *testing.T) {
		ts.Run(t,
			test.TestCase{
				Path:      "/tyk/oauth/clients/999999/" + authClientID,
				AdminAuth: true,
				Method:    http.MethodDelete,
				Code:      http.StatusOK,
			},
			test.TestCase{
				Path:      "/tyk/oauth/clients/999999/" + authClientID,
				AdminAuth: true,
				Method:    http.MethodGet,
				Code:      http.StatusNotFound,
				Delay:     1100 * time.Millisecond, // we need this to have deleted oauth client expired in memory cache
			},
		)
	})

	t.Run("Make sure token issued for deleted oauth-client cannot be used", func(t *testing.T) {
		ts.Run(t,
			test.TestCase{
				Path:    "/APIID/get",
				Headers: authHeader,
				Method:  http.MethodGet,
				Code:    http.StatusForbidden,
			},
			test.TestCase{
				Path:    "/APIID/get",
				Headers: authHeader,
				Method:  http.MethodGet,
				Code:    http.StatusForbidden,
			},
			test.TestCase{
				Path:    "/APIID/get",
				Headers: authHeader,
				Method:  http.MethodGet,
				Code:    http.StatusForbidden,
			},
		)
	})

}

func TestAPIClientAuthorizeTokenWithPolicy(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	t.Run("Client authorize token with policy request", func(t *testing.T) {
		param := make(url.Values)
		param.Set("response_type", "token")
		param.Set("redirect_uri", authRedirectUri)
		param.Set("client_id", authClientID)

		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		resp, err := ts.Run(t, test.TestCase{
			Path:      "/APIID/tyk/oauth/authorize-client/",
			AdminAuth: true,
			Data:      param.Encode(),
			Headers:   headers,
			Method:    http.MethodPost,
			Code:      http.StatusOK,
		})
		if err != nil {
			t.Error(err)
		}

		// check response
		asData := make(map[string]interface{})
		if err := json.NewDecoder(resp.Body).Decode(&asData); err != nil {
			t.Fatal("Decode failed:", err)
		}
		token, ok := asData["access_token"].(string)
		if !ok {
			t.Fatal("No access token found")
		}

		// Verify the token is correct
		session, ok := spec.AuthManager.KeyAuthorised(token)
		if !ok {
			t.Error("Key was not created (Can't find it)!")
		}

		if !reflect.DeepEqual(session.PolicyIDs(), []string{"TEST-4321"}) {
			t.Error("Policy not added to token!", session.PolicyIDs())
		}
	})
}

func getAuthCode(t *testing.T, ts *tykTestServer) map[string]string {
	param := make(url.Values)
	param.Set("response_type", "code")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	param.Set("key_rules", keyRules)

	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

	resp, err := ts.Run(t, test.TestCase{
		Path:      "/APIID/tyk/oauth/authorize-client/",
		AdminAuth: true,
		Data:      param.Encode(),
		Headers:   headers,
		Method:    http.MethodPost,
		Code:      http.StatusOK,
	})

	if err != nil {
		t.Error(err)
	}

	response := map[string]string{}
	json.NewDecoder(resp.Body).Decode(&response)
	return response
}

func TestGetClientTokens(t *testing.T) {
	t.Run("Without hashing", func(t *testing.T) {
		testGetClientTokens(t, false)
	})
	t.Run("With hashing", func(t *testing.T) {
		testGetClientTokens(t, true)
	})
}

func testGetClientTokens(t *testing.T, hashed bool) {
	globalConf := config.Global()
	// set tokens to be expired after 1 second
	globalConf.OauthTokenExpire = 1
	// cleanup tokens older than 3 seconds
	globalConf.OauthTokenExpiredRetainPeriod = 3

	globalConf.HashKeys = hashed

	config.SetGlobal(globalConf)

	defer resetTestConfig()

	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	clientID := uuid.NewV4().String()
	createTestOAuthClient(spec, clientID)

	// make three tokens
	tokensID := map[string]bool{}
	t.Run("Send three token requests", func(t *testing.T) {
		param := make(url.Values)
		param.Set("response_type", "token")
		param.Set("redirect_uri", authRedirectUri)
		param.Set("client_id", clientID)
		param.Set("client_secret", authClientSecret)
		param.Set("key_rules", keyRules)

		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		for i := 0; i < 3; i++ {
			resp, err := ts.Run(t, test.TestCase{
				Path:      "/APIID/tyk/oauth/authorize-client/",
				Data:      param.Encode(),
				AdminAuth: true,
				Headers:   headers,
				Method:    http.MethodPost,
				Code:      http.StatusOK,
			})
			if err != nil {
				t.Error(err)
			}

			response := map[string]interface{}{}
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				t.Fatal(err)
			}

			if hashed {
				// save tokens for future check
				tokensID[storage.HashKey(response["access_token"].(string))] = true
			} else {
				tokensID[response["access_token"].(string)] = true
			}
		}
	})

	// get list of tokens
	t.Run("Get list of tokens", func(t *testing.T) {
		resp, err := ts.Run(t, test.TestCase{
			Path:      fmt.Sprintf("/tyk/oauth/clients/999999/%s/tokens", clientID),
			AdminAuth: true,
			Method:    http.MethodGet,
			Code:      http.StatusOK,
		})
		if err != nil {
			t.Error(err)
		}

		tokensResp := []OAuthClientToken{}
		if err := json.NewDecoder(resp.Body).Decode(&tokensResp); err != nil {
			t.Fatal(err)
		}

		// check response
		if len(tokensResp) != len(tokensID) {
			t.Errorf("Wrong number of tokens received. Expected: %d. Got: %d", len(tokensID), len(tokensResp))
		}
		for _, token := range tokensResp {
			if !tokensID[token.Token] {
				t.Errorf("Token %s is not found in expected result. Expecting: %v", token.Token, tokensID)
			}
		}
	})

	t.Run("Get list of tokens after they expire", func(t *testing.T) {
		// sleep to wait until tokens expire
		time.Sleep(2 * time.Second)

		resp, err := ts.Run(t, test.TestCase{
			Path:      fmt.Sprintf("/tyk/oauth/clients/999999/%s/tokens", clientID),
			AdminAuth: true,
			Method:    http.MethodGet,
			Code:      http.StatusOK,
		})
		if err != nil {
			t.Error(err)
		}

		// check response
		tokensResp := []OAuthClientToken{}
		if err := json.NewDecoder(resp.Body).Decode(&tokensResp); err != nil {
			t.Fatal(err)
		}
		if len(tokensResp) > 0 {
			t.Errorf("Wrong number of tokens received. Expected 0 - all tokens expired. Got: %d", len(tokensResp))
		}
	})
}

type tokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func getToken(t *testing.T, ts *tykTestServer) tokenData {
	authData := getAuthCode(t, ts)

	param := make(url.Values)
	param.Set("grant_type", "authorization_code")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)
	param.Set("code", authData["code"])

	headers := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic MTIzNDphYWJiY2NkZA==",
	}

	resp, err := ts.Run(t, test.TestCase{
		Path:    "/APIID/oauth/token/",
		Data:    param.Encode(),
		Headers: headers,
		Method:  http.MethodPost,
		Code:    http.StatusOK,
	})

	if err != nil {
		t.Error(err)
	}

	response := tokenData{}
	json.NewDecoder(resp.Body).Decode(&response)
	return response
}

func TestOAuthClientCredsGrant(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	t.Run("Client credentials grant token request", func(t *testing.T) {
		param := make(url.Values)
		param.Set("grant_type", "client_credentials")
		param.Set("client_id", authClientID)
		param.Set("client_secret", authClientSecret)

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": "Basic MTIzNDphYWJiY2NkZA==",
		}

		resp, err := ts.Run(t, test.TestCase{
			Path:    "/APIID/oauth/token/",
			Data:    param.Encode(),
			Headers: headers,
			Method:  http.MethodPost,
			Code:    http.StatusOK,
		})
		if err != nil {
			t.Error(err)
		}

		// check response content
		response := tokenData{}
		json.NewDecoder(resp.Body).Decode(&response)
		if response.AccessToken == "" {
			t.Error("Access token is empty!")
		}
	})
}

func TestClientAccessRequest(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	authData := getAuthCode(t, &ts)

	t.Run("Exchane access code for token request", func(t *testing.T) {
		param := make(url.Values)
		param.Set("grant_type", "authorization_code")
		param.Set("redirect_uri", authRedirectUri)
		param.Set("client_id", authClientID)
		param.Set("code", authData["code"])

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": "Basic MTIzNDphYWJiY2NkZA==",
		}

		ts.Run(t, test.TestCase{
			Path:    "/APIID/oauth/token/",
			Data:    param.Encode(),
			Headers: headers,
			Method:  http.MethodPost,
			Code:    http.StatusOK,
		})
	})
}

func TestOAuthAPIRefreshInvalidate(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	// Step 1 create token
	tokenData := getToken(t, &ts)

	// Step 2 - invalidate the refresh token
	t.Run("Invalidate token request", func(t *testing.T) {
		param := make(url.Values)
		param.Set("api_id", "999999")
		resp, err := ts.Run(t, test.TestCase{
			Path:      "/tyk/oauth/refresh/" + tokenData.RefreshToken + "?" + param.Encode(),
			AdminAuth: true,
			Method:    http.MethodDelete,
			Code:      http.StatusOK,
		})
		if err != nil {
			t.Error(err)
		}

		newSuccess := apiModifyKeySuccess{}
		json.NewDecoder(resp.Body).Decode(&newSuccess)
		if newSuccess.Status != "ok" {
			t.Errorf("key not deleted, status error: %s\n", newSuccess.Status)
			t.Error(apisByID)
		}
		if newSuccess.Action != "deleted" {
			t.Errorf("Response is incorrect - action is not 'deleted': %s\n", newSuccess.Action)
		}
	})

	// Step 3 - try to refresh
	t.Run("Refresh token request", func(t *testing.T) {
		param := make(url.Values)
		param.Set("grant_type", "refresh_token")
		param.Set("redirect_uri", authRedirectUri)
		param.Set("client_id", authClientID)
		param.Set("refresh_token", tokenData.RefreshToken)
		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": "Basic MTIzNDphYWJiY2NkZA==",
		}
		ts.Run(t, test.TestCase{
			Path:    "/APIID/oauth/token/",
			Data:    param.Encode(),
			Headers: headers,
			Method:  http.MethodPost,
			Code:    http.StatusForbidden,
		})
	})
}

func TestClientRefreshRequest(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	tokenData := getToken(t, &ts)

	t.Run("Refresh token request", func(t *testing.T) {
		param := make(url.Values)
		param.Set("grant_type", "refresh_token")
		param.Set("redirect_uri", authRedirectUri)
		param.Set("client_id", authClientID)
		param.Set("refresh_token", tokenData.RefreshToken)

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": "Basic MTIzNDphYWJiY2NkZA==",
		}

		ts.Run(t, test.TestCase{
			Path:    "/APIID/oauth/token/",
			Data:    param.Encode(),
			Headers: headers,
			Method:  http.MethodPost,
			Code:    http.StatusOK,
		})
	})
}

func TestClientRefreshRequestDouble(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()

	createTestOAuthClient(spec, authClientID)

	tokenData := getToken(t, &ts)

	headers := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic MTIzNDphYWJiY2NkZA==",
	}

	// req 1
	token := ""
	t.Run("1st refresh token request", func(t *testing.T) {
		param := make(url.Values)
		param.Set("grant_type", "refresh_token")
		param.Set("redirect_uri", authRedirectUri)
		param.Set("client_id", authClientID)
		param.Set("refresh_token", tokenData.RefreshToken)

		resp, err := ts.Run(t, test.TestCase{
			Path:    "/APIID/oauth/token/",
			Data:    param.Encode(),
			Headers: headers,
			Method:  http.MethodPost,
			Code:    http.StatusOK,
		})
		if err != nil {
			t.Error(err)
		}
		responseData := make(map[string]interface{})
		json.NewDecoder(resp.Body).Decode(&responseData)
		var ok bool
		token, ok = responseData["refresh_token"].(string)
		if !ok {
			t.Fatal("No refresh token found")
		}
	})

	// req 2
	t.Run("2nd refresh token request", func(t *testing.T) {
		param := make(url.Values)
		param.Set("grant_type", "refresh_token")
		param.Set("redirect_uri", authRedirectUri)
		param.Set("client_id", authClientID)
		param.Set("refresh_token", token)

		ts.Run(t, test.TestCase{
			Path:    "/APIID/oauth/token/",
			Data:    param.Encode(),
			Headers: headers,
			Method:  http.MethodPost,
			Code:    http.StatusOK,
		})
	})
}

func TestTokenEndpointHeaders(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	spec := loadTestOAuthSpec()
	createTestOAuthClient(spec, authClientID)

	param := make(url.Values)
	param.Set("grant_type", "client_credentials")
	param.Set("redirect_uri", authRedirectUri)
	param.Set("client_id", authClientID)

	headers := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic MTIzNDphYWJiY2NkZA==",
	}

	securityAndCacheHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-XSS-Protection":          "1; mode=block",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"Cache-Control":             "no-cache, no-store, must-revalidate",
		"Pragma":                    "no-cache",
		"Expires":                   "0",
	}

	ts.Run(t, test.TestCase{
		Path:         "/APIID/oauth/token/",
		Data:         param.Encode(),
		Headers:      headers,
		Method:       http.MethodPost,
		Code:         http.StatusOK,
		HeadersMatch: securityAndCacheHeaders,
	})
}
