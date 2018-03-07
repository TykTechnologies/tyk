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

func loadTestOAuthSpec() *APISpec {
	spec := buildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "999999"
		spec.OrgID = "default"
		spec.Auth = apidef.Auth{
			AuthHeaderName: "authorization",
		}
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
	})[0]

	return spec
}

func createTestOAuthClient(spec *APISpec, clientID string) {
	// add a test client
	testPolicy := user.Policy{}
	testPolicy.Rate = 100
	testPolicy.Per = 1
	testPolicy.QuotaMax = -1
	testPolicy.QuotaRenewalRate = 1000000000

	policiesMu.Lock()
	policiesByID["TEST-4321"] = testPolicy
	policiesMu.Unlock()

	var redirectURI string
	// If separator is not set that means multiple redirect uris not supported
	if config.Global.OauthRedirectUriSeparator == "" {
		redirectURI = "http://client.oauth.com"

		// If separator config is set that means multiple redirect uris are supported
	} else {
		redirectURI = strings.Join([]string{"http://client.oauth.com", "http://client2.oauth.com", "http://client3.oauth.com"}, config.Global.OauthRedirectUriSeparator)
	}
	testClient := OAuthClient{
		ClientID:          clientID,
		ClientSecret:      authClientSecret,
		ClientRedirectURI: redirectURI,
		PolicyID:          "TEST-4321",
	}
	spec.OAuthManager.OsinServer.Storage.SetClient(testClient.ClientID, &testClient, false)
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
	oauthRedirectUriSeparator := config.Global.OauthRedirectUriSeparator
	defer func() {
		config.Global.OauthRedirectUriSeparator = oauthRedirectUriSeparator
	}()
	// Enable multiple Redirect URIs
	config.Global.OauthRedirectUriSeparator = ","

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
	oauthRedirectUriSeparator := config.Global.OauthRedirectUriSeparator
	defer func() {
		config.Global.OauthRedirectUriSeparator = oauthRedirectUriSeparator
	}()
	// Disable multiple Redirect URIs
	config.Global.OauthRedirectUriSeparator = ""

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
			t.Error("Policy not added to token!")
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
	// restore global config after test is done
	oauthTokenExpire := config.Global.OauthTokenExpire
	oauthTokenExpiredRetainPeriod := config.Global.OauthTokenExpiredRetainPeriod
	defer func() {
		config.Global.OauthTokenExpire = oauthTokenExpire
		config.Global.OauthTokenExpiredRetainPeriod = oauthTokenExpiredRetainPeriod
	}()

	// set tokens to be expired after 1 second
	config.Global.OauthTokenExpire = 1
	// cleanup tokens older than 3 seconds
	config.Global.OauthTokenExpiredRetainPeriod = 3

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

			// save tokens for future check
			tokensID[response["access_token"].(string)] = true
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
