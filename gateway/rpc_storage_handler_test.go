package gateway

import (
	"fmt"
	"github.com/TykTechnologies/gorpc"
	"github.com/magiconair/properties/assert"
	"testing"
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
			Revoke refresh token
	Keys:
		Remove key
		Update key
		UpdateKey with Quota reset


*/

const (
	RevokeOauthHashedToken = "RevokeOauthHashedToken"
	RevokeOauthToken = "RevokeOauthToken"
)

func buildStringEvent(eventType, token, apiId string) string {
	switch eventType {
	case RevokeOauthHashedToken:
		// string is as= {the-hashed-token}#hashed:{api-id}:oAuthRevokeToken
		return fmt.Sprintf("%s#hashed:%s:oAuthRevokeToken", token,apiId)
	case RevokeOauthToken:
		// string is as= {the-token}=:{api-id}:oAuthRevokeToken
		return fmt.Sprintf("%s:%s:oAuthRevokeToken", token,apiId)
	}
	return ""
}

func TestProcessKeySpaceChangesForOauth(t *testing.T){
	ts := StartTest()
	defer ts.Close()

	rpcListener  := RPCStorageHandler{
		KeyPrefix:        "rpc.listener.",
		SuppressRegister: true,
		HashKeys:         false,
	}

	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetKey", func(clientAddr, key string) (string, error) {
		return jsonMarshalString(CreateStandardSession()), nil
	})

	cases := []struct {
		TestName string
		Api *APISpec
		Event string
		RpcListener RPCStorageHandler
		Hashed bool
		token string
	}{
		{
			TestName:    "test1",
			Api:         nil,
			Event:       "",
			RpcListener: RPCStorageHandler{},
			Hashed: false,
			token: getToken(t, ts).AccessToken
		},
	}

	for _, tc := range cases{
		t.Run(tc.TestName, func(t *testing.T) {
			rpcListener  := RPCStorageHandler{
				KeyPrefix:        "rpc.listener.",
				SuppressRegister: true,
				HashKeys:         tc.Hashed,
			}
			//we got to set myApi.OAuthManager.OsinServer.Storage
			myApi := loadTestOAuthSpec()
			createTestOAuthClient(myApi, authClientID)

			GlobalSessionManager.Store().DeleteAllKeys()
			GlobalSessionManager.Store().SetKey(tc.token,tc.token,100)

			ss, err := GlobalSessionManager.Store().GetKey(v)
			if err != nil {
				t.Error("Key should be pre-loaded in store in order that the test perform the revoke action. Please check")
			}

			stringEvent := buildStringEvent(tc.Event,tc.token,myApi.APIID)
			rpcListener.ProcessKeySpaceChanges([]string{stringEvent})
			keyFound, err := GlobalSessionManager.Store().GetKey(tc.token)
			if err == nil {
				t.Error(" key session not removed ",keyFound,tc.Event)
			}else{
				assert.Equal(t,err.Error(),"key not found","expected error msg is 'key not found'")
			}
		})
	}
	//we got to set myApi.OAuthManager.OsinServer.Storage
	myApi := loadTestOAuthSpec()
	createTestOAuthClient(myApi, authClientID)

	// Step 1 create token
	tokenData := getToken(t, ts)
//	t.Log(GetStorageForApi(myApi.APIID))
	//init rpc listener
	//put some data there
	//check that is modified as intended
	//changes should be:
	// 1- for api keys
	// 2- for oauth
	// handle uses cases where its a hashed token
	// I have to create an api for oauth with storage and al the stuffs

//	rpc := startRPCMock(dispatcher)
	//defer stopRPCMock(rpc)

	//clear so we have it brand new
	GlobalSessionManager.Store().DeleteAllKeys()
	GlobalSessionManager.Store().SetKey(tokenData.AccessToken,tokenData.AccessToken,100)

	data := map[string]string{
		buildStringEvent(RevokeOauthHashedToken,tokenData.AccessToken,myApi.APIID):tokenData.AccessToken,
	}

	for k,v := range data{
		//ensure that before revoke, we have the key in storage
		ss, err := GlobalSessionManager.Store().GetKey(v)
		if err != nil {
			t.Error("Key should be pre-loaded in store in order that the test perform the revoke action. Please check")
		}

		rpcListener.ProcessKeySpaceChanges([]string{k})
		keyFound, err := GlobalSessionManager.Store().GetKey(v)
		if err == nil {
			t.Error(" key session not removed ",keyFound,v)
		}else{
			assert.Equal(t,err.Error(),"key not found","expected error msg is 'key not found'")
		}
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