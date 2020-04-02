package gateway

import (
	"testing"
)

func TestProcessKeySpaceChanges(t *testing.T){
	r := RPCStorageHandler{}
	GlobalSessionManager = SessionHandler(&DefaultSessionManager{})
	GlobalSessionManager.Store().DeleteAllKeys()
	//GlobalSessionManager.Store().se
	LoadSampleAPI(apiTestDef)

		//register some apis with api spec orgid
	//put some data in Global SessionManager:
	GlobalSessionManager.Store().SetKey('')
	// - oauth data: hashed, not hashed
	// - normal keys
	//Remove them via Process Key Space changes
	//get them, they should not exist anymore


	//check the values added in: SessionCache, RPCGlobalCache,
	r.ProcessKeySpaceChanges([]string{"sss"})
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