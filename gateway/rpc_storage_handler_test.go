package gateway

import (
	"fmt"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/lonelycode/osin"
	"github.com/magiconair/properties/assert"
)

const apiKeySpaceChangesTestDef = `{
	"api_id": "api-for-key-space-changes",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + TestHttpAny + `"
	}
}`

/*
	Oauth:
		Unhashed
			Revoke access token
			Revoke refresh token
		hashed
			Revoke access token
	Keys:
		Remove key
		Update key
		UpdateKey with Quota reset


*/

const (
	RevokeOauthHashedToken        = "RevokeOauthHashedToken"
	RevokeOauthToken              = "RevokeOauthToken"
	RevokeOauthRefreshToken       = "RevokeOauthRefreshToken"
	RevokeOauthRefreshHashedToken = "RevokeOauthRefreshHashedToken"
)

func buildStringEvent(eventType, token, apiId string) string {
	switch eventType {
	case RevokeOauthHashedToken:
		// string is as= {the-hashed-token}#hashed:{api-id}:oAuthRevokeToken
		token = storage.HashStr(token)
		return fmt.Sprintf("%s#hashed:%s:oAuthRevokeToken", token, apiId)
	case RevokeOauthToken:
		// string is as= {the-token}=:{api-id}:oAuthRevokeToken
		return fmt.Sprintf("%s:%s:oAuthRevokeToken", token, apiId)
	case RevokeOauthRefreshToken:
		// string is as= {the-token}=:{api-id}:oAuthRevokeToken
		return fmt.Sprintf("%s:%s:oAuthRevokeRefreshToken", token, apiId)
	case RevokeOauthRefreshHashedToken:
		// string is as= {the-token}=:{api-id}:oAuthRevokeToken
		return fmt.Sprintf("%s:%s:oAuthRevokeToken", token, apiId)
	}
	return ""
}

func getAccessToken(td tokenData) string {
	return td.AccessToken
}

func getRefreshToken(td tokenData) string {
	return td.RefreshToken
}

func TestProcessKeySpaceChangesForOauth(t *testing.T) {

	cases := []struct {
		TestName string
		Event    string
		Hashed   bool
		GetToken func(td tokenData) string
	}{
		{
			TestName: RevokeOauthToken,
			Event:    RevokeOauthToken,
			Hashed:   false,
			GetToken: getAccessToken,
		},
		{
			TestName: RevokeOauthHashedToken,
			Event:    RevokeOauthHashedToken,
			Hashed:   true,
			GetToken: getAccessToken,
		},
		{
			TestName: RevokeOauthRefreshToken,
			Event:    RevokeOauthRefreshToken,
			Hashed:   false,
			GetToken: getRefreshToken,
		},
	}

	for _, tc := range cases {
		t.Run(tc.TestName, func(t *testing.T) {
			ts := StartTest()
			defer ts.Close()

			globalConf := config.Global()
			globalConf.HashKeys = tc.Hashed
			config.SetGlobal(globalConf)

			rpcListener := RPCStorageHandler{
				KeyPrefix:        "rpc.listener.",
				SuppressRegister: true,
				HashKeys:         tc.Hashed,
			}

			myApi := loadTestOAuthSpec()
			oauthClient := createTestOAuthClient(myApi, authClientID)
			tokenData := getToken(t, ts)
			token := tc.GetToken(tokenData)

			var getKeyFromStore func(string) (string, error)
			if tc.Event == RevokeOauthRefreshToken {
				//Refresh token are threated in a different way due that they reside in a different level and we cannot access them directly
				client := new(OAuthClient)
				client.MetaData = oauthClient.MetaData
				client.Description = oauthClient.Description
				client.ClientSecret = oauthClient.GetSecret()
				client.PolicyID = oauthClient.PolicyID
				client.ClientRedirectURI = oauthClient.ClientRedirectURI

				storage := myApi.OAuthManager.OsinServer.Storage
				ret := &osin.AccessData{
					AccessToken:  tokenData.AccessToken,
					RefreshToken: tokenData.RefreshToken,
					Client:       client,
				}
				storage.SaveAccess(ret)

				getKeyFromStore = func(token string) (string, error) {
					accessData, err := storage.LoadRefresh(token)
					var refresh string
					if accessData != nil {
						refresh = accessData.RefreshToken
					}
					return refresh, err
				}
			} else {
				getKeyFromStore = GlobalSessionManager.Store().GetKey
				GlobalSessionManager.Store().DeleteAllKeys()
				GlobalSessionManager.Store().SetKey(token, token, 100)
				_, err := GlobalSessionManager.Store().GetKey(token)
				if err != nil {
					t.Error("Key should be pre-loaded in store in order that the test perform the revoke action. Please check")
				}
			}

			stringEvent := buildStringEvent(tc.Event, token, myApi.APIID)
			rpcListener.ProcessKeySpaceChanges([]string{stringEvent})
			found, err := getKeyFromStore(token)
			if err == nil {
				t.Error(" key not removed. event:", stringEvent, " found:", found)
			} else {
				assert.Equal(t, err.Error(), "key not found", "expected error msg is 'key not found'")
			}
		})
	}
}

/*
DATA

Oauth tokens already hashed
3fe3b6f861398968#hashed:5dab7b83c1d6482446afe5258302be7e:oAuthRevokeToken
735390b0f9ca79f9#hashed:5dab7b83c1d6482446afe5258302be7e:oAuthRevokeToken
7f51284ecf769dd4#hashed:5dab7b83c1d6482446afe5258302be7e:oAuthRevokeToken

Oauth token not hashed
eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6ImE4NGMwMzk0MzE4OTQ5Y2FiMTJiYjRhMWJkZjQ4ZWU0IiwiaCI6Im11cm11cjY0In0=:5dab7b83c1d6482446afe5258302be7e:oAuthRevokeToken

Revoke not hashed access token
eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6ImQ4MDc4NGM3YTIzYTRkYTE4NzVlMmIwMzZiMGJjYmE5IiwiaCI6Im11cm11cjY0In0=:5dab7b83c1d6482446afe5258302be7e:oAuthRevokeAccessToken

Revoke not hashed refresh token
MTBlNGI3NDEtNzAzNS00YzgyLWJmMTYtODYxNDgwNjQzN2U3:5dab7b83c1d6482446afe5258302be7e:oAuthRevokeRefreshToken

TOKENS

eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6IjViM2JhOTc0YTYxMjQ5Yzc5YmVhMTNmMWY3M2YyMTI0IiwiaCI6Im11cm11cjY0In0=:resetQuota
eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6IjViM2JhOTc0YTYxMjQ5Yzc5YmVhMTNmMWY3M2YyMTI0IiwiaCI6Im11cm11cjY0In0=


*/
