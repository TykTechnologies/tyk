package gateway

import "C"

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

// CoProcessDefaultKeyPrefix is used as a key prefix for this CP.
const CoProcessDefaultKeyPrefix = "coprocess-data:"

func getStorageForPython(ctx context.Context) *storage.RedisCluster {
	rc := storage.NewConnectionHandler(ctx)

	go rc.Connect(ctx, nil, &config.Config{})
	rc.WaitConnect(ctx)

	handler := &storage.RedisCluster{KeyPrefix: CoProcessDefaultKeyPrefix, ConnectionHandler: rc}
	handler.Connect()
	return handler
}

// TykStoreData is a CoProcess API function for storing data.
//
//export TykStoreData
func TykStoreData(CKey, CValue *C.char, CTTL C.int) {
	key := C.GoString(CKey)
	value := C.GoString(CValue)
	ttl := int64(CTTL)

	// Timeout storing data after 1 second
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	store := getStorageForPython(ctx)

	err := store.SetKey(key, value, ttl)
	if err != nil {
		log.WithError(err).Error("could not set key")
	}
}

// TykGetData is a CoProcess API function for fetching data.
//
//export TykGetData
func TykGetData(CKey *C.char) *C.char {
	key := C.GoString(CKey)

	// Timeout storing data after 1 second
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	store := getStorageForPython(ctx)

	val, err := store.GetKey(key)
	if err != nil {
		log.WithError(err).Error("could not get key")
	}

	return C.CString(val)
}

// GatewayFireSystemEvent declared as global variable, set during gw start
var GatewayFireSystemEvent func(name apidef.TykEvent, meta interface{})

// TykTriggerEvent is a CoProcess API function for triggering Tyk system events.
//
//export TykTriggerEvent
func TykTriggerEvent(CEventName, CPayload *C.char) {
	eventName := C.GoString(CEventName)
	payload := C.GoString(CPayload)

	GatewayFireSystemEvent(apidef.TykEvent(eventName), EventMetaDefault{
		Message: payload,
	})
}

// CoProcessLog is a bridge for using Tyk log from CP.
//
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

func cgoCString(in string) *C.char {
	return C.CString(in)
}

func cgoGoString(in *C.char) string {
	return C.GoString(in)
}

func cgoCint(in int) C.int {
	return C.int(in)
}
