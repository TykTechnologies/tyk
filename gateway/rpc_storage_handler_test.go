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
	// - oauth data: hashed, not hashed
	// - normal keys
	//Remove them via Process Key Space changes
	//get them, they should not exist anymore


	r.ProcessKeySpaceChanges([]string{"sss"})
}