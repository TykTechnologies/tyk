package gateway

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
	"github.com/lonelycode/osin"
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
				err := GlobalSessionManager.Store().SetRawKey(token, token, 100)
				assert.NoError(t, err)
				_, err = GlobalSessionManager.Store().GetRawKey(token)
				assert.NoError(t, err)
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

func TestProcessKeySpaceChanges_ResetQuota(t *testing.T) {
	rpcListener := RPCStorageHandler{
		KeyPrefix:        "rpc.listener.",
		SuppressRegister: true,
		HashKeys:         false,
	}

	GlobalSessionManager.Store().DeleteAllKeys()
	defer GlobalSessionManager.Store().DeleteAllKeys()

	g := StartTest()
	defer g.Close()

	api := BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/api"
	})[0]

	session, key := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{api.APIID: {
			APIID: api.APIID,
			Limit: user.APILimit{
				QuotaMax: 30,
			},
		}}
	})

	auth := map[string]string{
		headers.Authorization: key,
	}

	// Call 3 times
	_, _ = g.Run(t, []test.TestCase{
		{Path: "/api", Headers: auth, Code: http.StatusOK},
		{Path: "/api", Headers: auth, Code: http.StatusOK},
		{Path: "/api", Headers: auth, Code: http.StatusOK},
	}...)

	// AllowanceScope is api id.
	quotaKey := QuotaKeyPrefix + api.APIID + "-" + key
	quotaCounter, err := GlobalSessionManager.Store().GetRawKey(quotaKey)
	assert.NoError(t, err)
	assert.Equal(t, "3", quotaCounter)

	rpcListener.ProcessKeySpaceChanges([]string{key + ":resetQuota", key}, api.OrgID)

	// mock of key reload in mdcb environment
	err = GlobalSessionManager.UpdateSession(key, session, 0, false)
	assert.NoError(t, err)

	// Call 1 time
	_, _ = g.Run(t, test.TestCase{Path: "/api", Headers: auth, Code: http.StatusOK})

	// ProcessKeySpaceChanges should reset the quota counter, it should be 1 instead of 4.
	quotaCounter, err = GlobalSessionManager.Store().GetRawKey(quotaKey)
	assert.NoError(t, err)
	assert.Equal(t, "1", quotaCounter)
}
