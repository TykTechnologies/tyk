package gateway

/*
#include <stdlib.h>

typedef struct tyk_get_session_ret {
	char* session_buf;
	int buflen;
} tyk_get_session_ret;
*/
import "C"

import (
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/golang/protobuf/proto"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
	"unsafe"
)

// TykGetSessionRet is an alias for tyk_get_session_ret
type TykGetSessionRet C.tyk_get_session_ret

// CoProcessDefaultKeyPrefix is used as a key prefix for this CP.
const CoProcessDefaultKeyPrefix = "coprocess-data:"

// TODO: implement INCR, DECR?

// TykStoreData is a CoProcess API function for storing data.
//export TykStoreData
func TykStoreData(CKey, CValue *C.char, CTTL C.int) {
	key := C.GoString(CKey)
	value := C.GoString(CValue)
	ttl := int64(CTTL)

	store := storage.RedisCluster{KeyPrefix: CoProcessDefaultKeyPrefix}
	store.SetKey(key, value, ttl)
}

// TykGetData is a CoProcess API function for fetching data.
//export TykGetData
func TykGetData(CKey *C.char) *C.char {
	key := C.GoString(CKey)

	store := storage.RedisCluster{KeyPrefix: CoProcessDefaultKeyPrefix}
	// TODO: return error
	val, _ := store.GetKey(key)
	return C.CString(val)
}

// TykTriggerEvent is a CoProcess API function for triggering Tyk system events.
//export TykTriggerEvent
func TykTriggerEvent(CEventName, CPayload *C.char) {
	eventName := C.GoString(CEventName)
	payload := C.GoString(CPayload)

	FireSystemEvent(apidef.TykEvent(eventName), EventMetaDefault{
		Message: payload,
	})
}

// CoProcessLog is a bridge for using Tyk log from CP.
//export CoProcessLog
func CoProcessLog(CMessage, CLogLevel *C.char) {
	message := C.GoString(CMessage)
	logLevel := C.GoString(CLogLevel)
	switch logLevel {
	case "debug":
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Debug(message)
	case "error":
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(message)
	case "warning":
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Warning(message)
	default:
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Info(message)
	}
}

// TykSetSession is a CoProcess API function for creating sessions.
//export TykSetSession
func TykSetSession(CToken, CRawSession *C.char, length C.int) C.int {
	token := C.GoString(CToken)
	rawSession := C.GoBytes(unsafe.Pointer(CRawSession), length)
	pbSession := coprocess.SessionState{}
	err := proto.Unmarshal(rawSession, &pbSession)
	if err != nil {
		return -1
	}
	session := TykSessionState(&pbSession)
	if err := GlobalSessionManager.UpdateSession(token, session, session.SessionLifetime, false); err != nil {
		return -1
	}
	return 0
}

// TykGetSession is a CP function for retrieving existing sessions.
//export TykGetSession
func TykGetSession(COrgID, CToken *C.char) *C.tyk_get_session_ret {
	orgID := C.GoString(COrgID)
	token := C.GoString(CToken)
	store := &storage.RedisCluster{KeyPrefix: "apikey-", HashKeys: config.Global().HashKeys}
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			OrgID: orgID,
		},
		GlobalConfig: config.Global(),
		AuthManager:  &DefaultAuthorisationManager{store},
	}
	baseMW := BaseMiddleware{
		Spec: spec,
	}
	session, exists :=baseMW.CheckSessionAndIdentityForValidKey(token, nil)
	if !exists {
		return nil
	}
	pbSession := ProtoSessionState(&session)
	rawSession, err := proto.Marshal(pbSession)
	if err != nil {
		return nil
	}
	return tykGetSessionRet(rawSession)
}