// +build coprocess
// +build !grpc

package main

/*
#include <stdio.h>

#include "coprocess/sds/sds.h"

#include "coprocess/api.h"

#ifdef ENABLE_PYTHON
#include "coprocess/python/dispatcher.h"
#include "coprocess/python/binding.h"
#endif
*/
import "C"

import (
	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/tykcommon"
)

// CoProcessDefaultKeyPrefix is used as a key prefix for this CP.
const CoProcessDefaultKeyPrefix string = "coprocess-data:"

// TODO: implement INCR, DECR?

// TykStoreData is a CoProcess API function for storing data.
//export TykStoreData
func TykStoreData(CKey *C.char, CValue *C.char, CTTL C.int) {
	key := C.GoString(CKey)
	value := C.GoString(CValue)
	ttl := int64(CTTL)

	thisStorageHandler := GetGlobalLocalStorageHandler(CoProcessDefaultKeyPrefix, false)
	thisStorageHandler.SetKey(key, value, ttl)
}

// TykGetData is a CoProcess API function for fetching data.
//export TykGetData
func TykGetData(CKey *C.char) *C.char {
	key := C.GoString(CKey)

	thisStorageHandler := GetGlobalLocalStorageHandler(CoProcessDefaultKeyPrefix, false)
	// TODO: return error
	val, _ := thisStorageHandler.GetKey(key)
	return C.CString(val)
}

// TykTriggerEvent is a CoProcess API function for triggering Tyk system events.
//export TykTriggerEvent
func TykTriggerEvent(CEventName *C.char, CPayload *C.char) {
	eventName := C.GoString(CEventName)
	payload := C.GoString(CPayload)

	FireSystemEvent(tykcommon.TykEvent(eventName), EventMetaDefault{
		Message: payload,
	})
}

// CoProcessLog is a bridge for using Tyk log from CP.
//export CoProcessLog
func CoProcessLog(CMessage *C.char, CLogLevel *C.char) {
	var message, logLevel string
	message = C.GoString(CMessage)
	logLevel = C.GoString(CLogLevel)

	switch logLevel {
	case "debug":
		log.WithFields(logrus.Fields{
			"prefix": CoProcessName,
		}).Debug(message)
	case "error":
		log.WithFields(logrus.Fields{
			"prefix": CoProcessName,
		}).Error(message)
	case "warning":
		log.WithFields(logrus.Fields{
			"prefix": CoProcessName,
		}).Warning(message)
	default:
		log.WithFields(logrus.Fields{
			"prefix": CoProcessName,
		}).Info(message)
	}
}
