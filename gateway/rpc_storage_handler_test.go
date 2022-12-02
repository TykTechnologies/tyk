package gateway

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"

	"github.com/lonelycode/osin"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
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
			ts := StartTest(nil)
			defer ts.Close()

			globalConf := ts.Gw.GetConfig()
			globalConf.HashKeys = tc.Hashed
			ts.Gw.SetConfig(globalConf)

			rpcListener := RPCStorageHandler{
				KeyPrefix:        "rpc.listener.",
				SuppressRegister: true,
				HashKeys:         tc.Hashed,
				Gw:               ts.Gw,
			}

			myApi := ts.LoadTestOAuthSpec()
			oauthClient := ts.createTestOAuthClient(myApi, authClientID)
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
				getKeyFromStore = ts.Gw.GlobalSessionManager.Store().GetKey
				ts.Gw.GlobalSessionManager.Store().DeleteAllKeys()
				err := ts.Gw.GlobalSessionManager.Store().SetRawKey(token, token, 100)
				assert.NoError(t, err)
				_, err = ts.Gw.GlobalSessionManager.Store().GetRawKey(token)
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

	g := StartTest(nil)
	defer g.Close()

	rpcListener := RPCStorageHandler{
		KeyPrefix:        "rpc.listener.",
		SuppressRegister: true,
		HashKeys:         false,
		Gw:               g.Gw,
	}

	g.Gw.GlobalSessionManager.Store().DeleteAllKeys()
	defer g.Gw.GlobalSessionManager.Store().DeleteAllKeys()

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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
		header.Authorization: key,
	}

	// Call 3 times
	_, _ = g.Run(t, []test.TestCase{
		{Path: "/api", Headers: auth, Code: http.StatusOK},
		{Path: "/api", Headers: auth, Code: http.StatusOK},
		{Path: "/api", Headers: auth, Code: http.StatusOK},
	}...)

	// AllowanceScope is api id.
	quotaKey := QuotaKeyPrefix + api.APIID + "-" + key
	quotaCounter, err := g.Gw.GlobalSessionManager.Store().GetRawKey(quotaKey)
	assert.NoError(t, err)
	assert.Equal(t, "3", quotaCounter)

	rpcListener.ProcessKeySpaceChanges([]string{key + ":resetQuota", key}, api.OrgID)

	// mock of key reload in mdcb environment
	err = g.Gw.GlobalSessionManager.UpdateSession(key, session, 0, false)
	assert.NoError(t, err)

	// Call 1 time
	_, _ = g.Run(t, test.TestCase{Path: "/api", Headers: auth, Code: http.StatusOK})

	// ProcessKeySpaceChanges should reset the quota counter, it should be 1 instead of 4.
	quotaCounter, err = g.Gw.GlobalSessionManager.Store().GetRawKey(quotaKey)
	assert.NoError(t, err)
	assert.Equal(t, "1", quotaCounter)
}

// TestRPCUpdateKey check that on update key event the key still exist in worker redis
func TestRPCUpdateKey(t *testing.T) {

	cases := []struct {
		TestName     string
		Hashed       bool
		EventPostfix string
	}{
		{
			TestName:     "TestRPCUpdateKey unhashed",
			Hashed:       false,
			EventPostfix: "",
		}, {
			TestName:     "TestRPCUpdateKey hashed",
			Hashed:       true,
			EventPostfix: ":hashed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.TestName, func(t *testing.T) {
			g := StartTest(func(globalConf *config.Config) {
				globalConf.HashKeys = tc.Hashed
			})
			defer g.Close()

			rpcListener := RPCStorageHandler{
				KeyPrefix:        "rpc.listener.",
				SuppressRegister: true,
				HashKeys:         tc.Hashed,
				Gw:               g.Gw,
			}

			g.Gw.GlobalSessionManager.Store().DeleteAllKeys()
			defer g.Gw.GlobalSessionManager.Store().DeleteAllKeys()

			api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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
				header.Authorization: key,
			}

			_, _ = g.Run(t, []test.TestCase{
				{Path: "/api", Headers: auth, Code: http.StatusOK},
			}...)

			tags := []string{"test"}
			session.Tags = tags

			err := g.Gw.GlobalSessionManager.UpdateSession(key, session, 0, tc.Hashed)
			assert.NoError(t, err)

			rpcListener.ProcessKeySpaceChanges([]string{"apikey-" + key + tc.EventPostfix}, api.OrgID)
			myUpdatedSession, newSessFound := g.Gw.GlobalSessionManager.SessionDetail(api.OrgID, key, tc.Hashed)

			assert.True(t, newSessFound, "key should be found")
			assert.Equal(t, tags, myUpdatedSession.Tags)
		})
	}
}
