package gateway

import (
	"github.com/TykTechnologies/gorpc"
	"testing"
)

const apiKeySpaceChangesTestDef = `{
	"api_id": "apiKeySpaceChangesTestDefID",
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

func TestProcessKeySpaceChanges(t *testing.T){
	r := RPCStorageHandler{}
	//GlobalSessionManager = SessionHandler(&DefaultSessionManager{})
	GlobalSessionManager.Store().DeleteAllKeys()
	//GlobalSessionManager.Store().se
	LoadSampleAPI(apiKeySpaceChangesTestDef)

	//register some apis with api spec orgid

	// Dynamically restart RPC layer

	//============
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetKey", func(clientAddr, key string) (string, error) {
		return jsonMarshalString(CreateStandardSession()), nil
	})

	rpc := startRPCMock(dispatcher)
	defer stopRPCMock(rpc)

	data := map[string]string{
		"3fe3b6f861398968#hashed:apiKeySpaceChangesTestDefID:oAuthRevokeToken" : "3fe3b6f861398968",//works
		"eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6ImE4NGMwMzk0MzE4OTQ5Y2FiMTJiYjRhMWJkZjQ4ZWU0IiwiaCI6Im11cm11cjY0In0=:apiKeySpaceChangesTestDefID:oAuthRevokeToken":"eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6ImE4NGMwMzk0MzE4OTQ5Y2FiMTJiYjRhMWJkZjQ4ZWU0IiwiaCI6Im11cm11cjY0In0=",
		//"eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6ImQ4MDc4NGM3YTIzYTRkYTE4NzVlMmIwMzZiMGJjYmE5IiwiaCI6Im11cm11cjY0In0=:apiKeySpaceChangesTestDefID:oAuthRevokeAccessToken":"eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6ImQ4MDc4NGM3YTIzYTRkYTE4NzVlMmIwMzZiMGJjYmE5IiwiaCI6Im11cm11cjY0In0=",
		//"MTBlNGI3NDEtNzAzNS00YzgyLWJmMTYtODYxNDgwNjQzN2U3:apiKeySpaceChangesTestDefID:oAuthRevokeRefreshToken":"MTBlNGI3NDEtNzAzNS00YzgyLWJmMTYtODYxNDgwNjQzN2U3",
		//"eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6IjViM2JhOTc0YTYxMjQ5Yzc5YmVhMTNmMWY3M2YyMTI0IiwiaCI6Im11cm11cjY0In0=:resetQuota":"eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6IjViM2JhOTc0YTYxMjQ5Yzc5YmVhMTNmMWY3M2YyMTI0IiwiaCI6Im11cm11cjY0In0=",
		//"eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6IjViM2JhOTc0YTYxMjQ5Yzc5YmVhMTNmMWY3M2YyMTI0IiwiaCI6Im11cm11cjY0In0=":"eyJvcmciOiI1ZTIwOTFjNGQ0YWVmY2U2MGMwNGZiOTIiLCJpZCI6IjViM2JhOTc0YTYxMjQ5Yzc5YmVhMTNmMWY3M2YyMTI0IiwiaCI6Im11cm11cjY0In0=",
	}

	keys := []string{}
	for k,v := range data{
		GlobalSessionManager.Store().SetKey(v,v,100)
		keys = append(keys, k)
	}


	// - oauth data: hashed, not hashed
	// - normal keys
	//Remove them via Process Key Space changes
	//get them, they should not exist anymore


	//check the values added in: SessionCache, RPCGlobalCache,
	//r.ProcessKeySpaceChanges(keys)

	for k,v := range data{
		r.ProcessKeySpaceChanges([]string{k})
		_, err := GlobalSessionManager.Store().GetKey(v)

		t.Log("============")
		if err == nil {
			t.Error(" key session not removed: ", err.Error())
		}else{

			if err.Error() == "key not found" {
				t.Log("key removed correctly")
			}
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