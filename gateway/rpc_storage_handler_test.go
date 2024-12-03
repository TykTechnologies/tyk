package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/rpc"

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
	test.Exclusive(t) // Uses DeleteAllKeys, need to limit parallelism.

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

				storage := myApi.OAuthManager.Storage()
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
				ts.Gw.GlobalSessionManager.Store().DeleteAllKeys() // exclusive
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
	test.Exclusive(t) // Uses DeleteAllKeys, need to limit parallelism.

	g := StartTest(nil)
	defer g.Close()

	rpcListener := RPCStorageHandler{
		KeyPrefix:        "rpc.listener.",
		SuppressRegister: true,
		HashKeys:         false,
		Gw:               g.Gw,
	}

	g.Gw.GlobalSessionManager.Store().DeleteAllKeys()       // exclusive
	defer g.Gw.GlobalSessionManager.Store().DeleteAllKeys() // exclusive

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
	test.Exclusive(t) // Uses DeleteAllKeys, need to limit parallelism.

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

			g.Gw.GlobalSessionManager.Store().DeleteAllKeys()       // exclusive
			defer g.Gw.GlobalSessionManager.Store().DeleteAllKeys() // exclusive

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

func TestGetGroupLoginCallback(t *testing.T) {
	test.Exclusive(t) // Uses DeleteAllKeys, need to limit parallelism.

	tcs := []struct {
		testName                 string
		syncEnabled              bool
		givenKey                 string
		givenGroup               string
		expectedCallbackResponse model.GroupLoginRequest
	}{
		{
			testName:                 "sync disabled",
			syncEnabled:              false,
			givenKey:                 "key",
			givenGroup:               "group",
			expectedCallbackResponse: model.GroupLoginRequest{UserKey: "key", GroupID: "group"},
		},
		{
			testName:                 "sync enabled",
			syncEnabled:              true,
			givenKey:                 "key",
			givenGroup:               "group",
			expectedCallbackResponse: model.GroupLoginRequest{UserKey: "key", GroupID: "group", ForceSync: true},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.testName, func(t *testing.T) {
			ts := StartTest(func(globalConf *config.Config) {
				globalConf.SlaveOptions.SynchroniserEnabled = tc.syncEnabled
			})
			defer ts.Close()
			defer ts.Gw.GlobalSessionManager.Store().DeleteAllKeys() // exclusive

			rpcListener := RPCStorageHandler{
				KeyPrefix:        "rpc.listener.",
				SuppressRegister: true,
				Gw:               ts.Gw,
			}

			expectedNodeInfo := model.NodeData{
				NodeID:      ts.Gw.GetNodeID(),
				GroupID:     "",
				APIKey:      "",
				TTL:         10,
				Tags:        nil,
				NodeVersion: VERSION,
				Health:      ts.Gw.getHealthCheckInfo(),
				Stats: model.GWStats{
					APIsCount:     0,
					PoliciesCount: 0,
				},
				HostDetails: model.HostDetails{
					Hostname: ts.Gw.hostDetails.Hostname,
					PID:      ts.Gw.hostDetails.PID,
					Address:  ts.Gw.hostDetails.Address,
				},
			}

			nodeData, err := json.Marshal(expectedNodeInfo)
			assert.Nil(t, err)

			tc.expectedCallbackResponse.Node = nodeData

			fn := rpcListener.getGroupLoginCallback(tc.syncEnabled)
			groupLogin, ok := fn(tc.givenKey, tc.givenGroup).(model.GroupLoginRequest)
			assert.True(t, ok)
			assert.Equal(t, tc.expectedCallbackResponse, groupLogin)
		})
	}

}

func TestRPCStorageHandler_BuildNodeInfo(t *testing.T) {
	tcs := []struct {
		testName         string
		givenTs          func() *Test
		expectedNodeInfo model.NodeData
	}{
		{
			testName: "base",
			givenTs: func() *Test {
				ts := StartTest(func(globalConf *config.Config) {
				})
				return ts
			},
			expectedNodeInfo: model.NodeData{
				GroupID:     "",
				APIKey:      "",
				TTL:         10,
				Tags:        nil,
				NodeVersion: VERSION,
				Stats: model.GWStats{
					APIsCount:     0,
					PoliciesCount: 0,
				},
			},
		},
		{
			testName: "custom conf",
			givenTs: func() *Test {
				ts := StartTest(func(globalConf *config.Config) {
					globalConf.SlaveOptions.GroupID = "group"
					globalConf.DBAppConfOptions.Tags = []string{"tag1"}
					globalConf.LivenessCheck.CheckDuration = 1000000000
					globalConf.SlaveOptions.APIKey = "apikey-test"
				})

				return ts
			},
			expectedNodeInfo: model.NodeData{
				GroupID:     "group",
				APIKey:      "apikey-test",
				TTL:         1,
				Tags:        []string{"tag1"},
				NodeVersion: VERSION,
				Stats: model.GWStats{
					APIsCount:     0,
					PoliciesCount: 0,
				},
			},
		},
		{
			testName: "with loaded apis and policies",
			givenTs: func() *Test {
				ts := StartTest(func(globalConf *config.Config) {
					globalConf.SlaveOptions.GroupID = "group"
					globalConf.DBAppConfOptions.Tags = []string{"tag1"}
					globalConf.LivenessCheck.CheckDuration = 1000000000
				})

				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.APIID = "test"
					spec.UseKeylessAccess = false
					spec.Auth.UseParam = true
					spec.OrgID = "default"
				})

				ts.CreatePolicy(func(p *user.Policy) {
					p.Partitions.RateLimit = true
					p.Tags = []string{"p1-tag"}
					p.MetaData = map[string]interface{}{
						"p1-meta": "p1-value",
					}
				})
				return ts
			},
			expectedNodeInfo: model.NodeData{
				GroupID:     "group",
				TTL:         1,
				Tags:        []string{"tag1"},
				NodeVersion: VERSION,
				Stats: model.GWStats{
					APIsCount:     1,
					PoliciesCount: 1,
				},
			},
		},
		{
			testName: "with node_id",
			givenTs: func() *Test {
				ts := StartTest(func(globalConf *config.Config) {
					globalConf.SlaveOptions.GroupID = "group"
					globalConf.DBAppConfOptions.Tags = []string{"tag1", "tag2"}
					globalConf.LivenessCheck.CheckDuration = 1000000000
				})

				ts.Gw.SetNodeID("test-node-id")
				return ts
			},
			expectedNodeInfo: model.NodeData{
				NodeID:      "test-node-id",
				GroupID:     "group",
				TTL:         1,
				Tags:        []string{"tag1", "tag2"},
				NodeVersion: VERSION,
				Stats: model.GWStats{
					APIsCount:     0,
					PoliciesCount: 0,
				},
			},
		},
		{
			testName: "with segmented node",
			givenTs: func() *Test {
				ts := StartTest(func(globalConf *config.Config) {
					globalConf.SlaveOptions.GroupID = "group"
					globalConf.DBAppConfOptions.Tags = []string{"tag1", "tag2"}
					globalConf.LivenessCheck.CheckDuration = 1000000000
					globalConf.DBAppConfOptions.NodeIsSegmented = true
				})

				ts.Gw.SetNodeID("test-node-id")
				return ts
			},
			expectedNodeInfo: model.NodeData{
				NodeID:          "test-node-id",
				GroupID:         "group",
				TTL:             1,
				Tags:            []string{"tag1", "tag2"},
				NodeIsSegmented: true,
				NodeVersion:     VERSION,
				Stats: model.GWStats{
					APIsCount:     0,
					PoliciesCount: 0,
				},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.testName, func(t *testing.T) {
			ts := tc.givenTs()
			defer ts.Close()

			r := &RPCStorageHandler{Gw: ts.Gw}

			tc.expectedNodeInfo.Health = ts.Gw.getHealthCheckInfo()

			if tc.expectedNodeInfo.NodeID == "" {
				tc.expectedNodeInfo.NodeID = ts.Gw.GetNodeID()
			}

			if tc.expectedNodeInfo.HostDetails.Hostname == "" {
				tc.expectedNodeInfo.HostDetails = model.HostDetails{
					Hostname: ts.Gw.hostDetails.Hostname,
					PID:      ts.Gw.hostDetails.PID,
					Address:  ts.Gw.hostDetails.Address,
				}
			}

			expected, err := json.Marshal(tc.expectedNodeInfo)
			assert.Nil(t, err)

			result := r.buildNodeInfo()

			assert.Equal(t, expected, result)
		})
	}
}

func TestRPCStorageHandler_Disconnect(t *testing.T) {
	t.Run("disconnect error", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		r := &RPCStorageHandler{Gw: ts.Gw}

		err := r.Disconnect()
		expectedErr := errors.New("RPCStorageHandler: rpc is either down or was not configured")
		assert.EqualError(t, err, expectedErr.Error())
	})
}

func TestGetRawKey(t *testing.T) {

	t.Run("rpc cache enabled - normal key", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.SlaveOptions.EnableRPCCache = true
		})
		defer ts.Close()

		rpcListener := RPCStorageHandler{
			KeyPrefix:        "rpc.listener.",
			SuppressRegister: true,
			Gw:               ts.Gw,
		}

		// first call should fail - key not found
		givenKey := "test-key"
		_, err := rpcListener.GetRawKey(givenKey)
		assert.NotNil(t, err)
		assert.Equal(t, "key not found", err.Error())

		// second call still fail but from cache
		_, err = rpcListener.GetRawKey(givenKey)
		assert.NotNil(t, err)
		assert.Equal(t, "key not found", err.Error())

		// we override the key in the cache
		rpcListener.Gw.RPCGlobalCache.Set(givenKey, "test-value", -1)
		defer rpcListener.Gw.RPCGlobalCache.Delete(givenKey)

		// third call should succeed
		value, err := rpcListener.GetRawKey(givenKey)
		assert.Nil(t, err)
		assert.Equal(t, "test-value", value)
	})
	t.Run("rpc cache enabled - cert key", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.SlaveOptions.EnableRPCCache = true
		})
		defer ts.Close()

		rpcListener := RPCStorageHandler{
			KeyPrefix:        "rpc.listener.",
			SuppressRegister: true,
			Gw:               ts.Gw,
		}

		// first call should fail - key not found
		givenKey := "cert-test-key"
		_, err := rpcListener.GetRawKey(givenKey)
		assert.NotNil(t, err)
		assert.Equal(t, "key not found", err.Error())

		// second call still fail but from cache
		_, err = rpcListener.GetRawKey(givenKey)
		assert.NotNil(t, err)
		assert.Equal(t, "key not found", err.Error())

		// we override the key in the cache
		rpcListener.Gw.RPCCertCache.Set(givenKey, "test-value", -1)
		defer rpcListener.Gw.RPCCertCache.Delete(givenKey)

		// third call should succeed
		value, err := rpcListener.GetRawKey(givenKey)
		assert.Nil(t, err)
		assert.Equal(t, "test-value", value)
	})

	t.Run("MDCB down, return mdcb lost connection err", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.SlaveOptions.EnableRPCCache = true
		})
		defer ts.Close()
		rpc.SetEmergencyMode(t, true)
		rpcListener := RPCStorageHandler{
			KeyPrefix:        "rpc.listener.",
			SuppressRegister: true,
			Gw:               ts.Gw,
		}

		_, err := rpcListener.GetRawKey("any-key")
		assert.Equal(t, storage.ErrMDCBConnectionLost, err)
	})
}

func TestDeleteUsingTokenID(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.SlaveOptions.EnableRPCCache = true
	})
	defer ts.Close()

	rpcListener := RPCStorageHandler{
		KeyPrefix:        "rpc.listener.",
		SuppressRegister: true,
		Gw:               ts.Gw,
	}

	t.Run("key could not be removed by base64 key ID but exist by custom key ID", func(t *testing.T) {
		// create a custom key
		const customKey = "my-custom-key"
		orgId := "default"
		session := CreateStandardSession()
		session.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}
		client := GetTLSClient(nil, nil)

		// creates a key and rename it
		resp, err := ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/keys/" + customKey,
			Data: session, Client: client, Code: http.StatusOK})
		assert.Nil(t, err)
		defer func() {
			err = resp.Body.Close()
			assert.Nil(t, err)
		}()
		body, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)
		keyResp := apiModifyKeySuccess{}

		err = json.Unmarshal(body, &keyResp)
		assert.NoError(t, err)

		// trick to change key name from base64 to custom (emulates keys as apikey-mycustomkey)
		val, err := ts.Gw.GlobalSessionManager.Store().GetRawKey("apikey-" + keyResp.Key)
		assert.Nil(t, err)
		err = ts.Gw.GlobalSessionManager.Store().SetKey(customKey, val, -1)
		assert.Nil(t, err)

		removed := ts.Gw.GlobalSessionManager.Store().DeleteRawKey("apikey-" + keyResp.Key)
		assert.True(t, removed)

		status, err := rpcListener.deleteUsingTokenID(keyResp.Key, orgId, false, 404)
		assert.Nil(t, err)
		// it was found
		assert.Equal(t, http.StatusOK, status)
		// it should not exist anymore
		_, err = ts.Gw.GlobalSessionManager.Store().GetKey(customKey)
		assert.ErrorIs(t, storage.ErrKeyNotFound, err)
	})

	t.Run("status not found and TokenID do not exist", func(t *testing.T) {
		status, err := rpcListener.deleteUsingTokenID("custom-key", "orgID", false, 404)
		assert.Nil(t, err)
		assert.Equal(t, 404, status)
	})
}
