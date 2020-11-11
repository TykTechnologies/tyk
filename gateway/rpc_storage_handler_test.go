package gateway

import (
	"fmt"
	"testing"

	"github.com/TykTechnologies/osin"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/stretchr/testify/assert"
)

const (
	RevokeOauthHashedToken        = "RevokeOauthHashedToken"
	RevokeOauthToken              = "RevokeOauthToken"
	RevokeOauthRefreshToken       = "RevokeOauthRefreshToken"
	RevokeOauthRefreshHashedToken = "RevokeOauthRefreshHashedToken" // we do  not support hashed refresh tokens yet

	DefaultOrg = "default-org-id"
)

func buildStringEvent(eventType, token, apiId string) string {
	switch eventType {
	case RevokeOauthHashedToken:
		// string is as= {the-hashed-token}#hashed:{api-id}:oAuthRevokeToken
		token = storage.HashStr(token)
		return fmt.Sprintf("%s#hashed:%s:oAuthRevokeToken", token, apiId)
	case RevokeOauthToken:
		// string is as= {the-token}:{api-id}:oAuthRevokeToken
		return fmt.Sprintf("%s:%s:oAuthRevokeToken", token, apiId)
	case RevokeOauthRefreshToken:
		// string is as= {the-token}:{api-id}:oAuthRevokeToken
		return fmt.Sprintf("%s:%s:oAuthRevokeRefreshToken", token, apiId)
	case RevokeOauthRefreshHashedToken:
		// string is as= {the-token}:{api-id}:oAuthRevokeToken
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
					t.Fatal("Key should be pre-loaded in store previously so the test can perform the revoke action.")
				}
			}

			stringEvent := buildStringEvent(tc.Event, token, myApi.APIID)
			rpcListener.ProcessKeySpaceChanges([]string{stringEvent}, myApi.OrgID)
			found, err := getKeyFromStore(token)
			if err == nil {
				t.Error(" key not removed. event:", stringEvent, " found:", found)
			} else {
				assert.Equal(t, err.Error(), "key not found", "expected error msg is 'key not found'")
			}
		})
	}
}
