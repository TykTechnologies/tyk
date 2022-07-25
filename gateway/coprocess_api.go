package gateway

import "C"

import (
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"
)

var (
	// Populated on CoProcessInit:
	cgoRedisController *storage.RedisController
)

// CoProcessDefaultKeyPrefix is used as a key prefix for this CP.
const CoProcessDefaultKeyPrefix = "coprocess-data:"

// TykStoreData is a CoProcess API function for storing data.
//export TykStoreData
func TykStoreData(CKey, CValue *C.char, CTTL C.int) {
	key := C.GoString(CKey)
	value := C.GoString(CValue)
	ttl := int64(CTTL)
	store := storage.RedisCluster{KeyPrefix: CoProcessDefaultKeyPrefix, RedisController: cgoRedisController}
	err := store.SetKey(key, value, ttl)
	if err != nil {
		log.WithError(err).Error("could not set key")
	}
}

// TykGetData is a CoProcess API function for fetching data.
//export TykGetData
func TykGetData(CKey *C.char) *C.char {
	key := C.GoString(CKey)

	store := storage.RedisCluster{KeyPrefix: CoProcessDefaultKeyPrefix, RedisController: cgoRedisController}
	// TODO: return error
	val, _ := store.GetKey(key)
	return C.CString(val)
}

// cgoTykStoreData wraps TykStoreData for test usage:
func cgoTykStoreData(key string, value string, ttl int) {
	keyStr := C.CString(key)
	valueStr := C.CString(value)
	TykStoreData(keyStr, valueStr, C.int(ttl))
}

// cgoTykStoreData wraps TykGetData for test usage:
func cgoTykGetData(key string) string {
	keyStr := C.CString(key)
	valStr := TykGetData(keyStr)
	return C.GoString(valStr)
}

// GatewayFireSystemEvent declared as global variable, set during gw start
var GatewayFireSystemEvent func(name apidef.TykEvent, meta interface{})

// TykTriggerEvent is a CoProcess API function for triggering Tyk system events.
//export TykTriggerEvent
func TykTriggerEvent(CEventName, CPayload *C.char) {
	eventName := C.GoString(CEventName)
	payload := C.GoString(CPayload)

	GatewayFireSystemEvent(apidef.TykEvent(eventName), EventMetaDefault{
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
