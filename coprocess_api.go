// +build coprocess

package main

/*
#include <stdio.h>

#include "coprocess/sds/sds.h"

#include "coprocess/api.h"

#include "coprocess/python/dispatcher.h"
#include "coprocess/python/binding.h"
*/
import "C"

import(
  "github.com/TykTechnologies/tykcommon"
)

const CoprocessDefaultKeyPrefix string = "coprocess-data:"

//export TykStoreData
func TykStoreData( CKey *C.char, CValue *C.char, CTTL C.int ) {
  // Store or cache some data in Redis, INCR, DECR?
  key := C.GoString(CKey)
  value := C.GoString(CValue)
  ttl := int64(CTTL)

  thisStorageHandler := GetGlobalLocalStorageHandler(CoprocessDefaultKeyPrefix, false)
  thisStorageHandler.SetKey(key, value, ttl)
}

//export TykGetData
func TykGetData( CKey *C.char ) *C.char {
  key := C.GoString(CKey)

  thisStorageHandler := GetGlobalLocalStorageHandler(CoprocessDefaultKeyPrefix, false)
  // TODO: return error
  val, _ := thisStorageHandler.GetKey(key)
  return C.CString(val)
}

//export TykTriggerEvent
func TykTriggerEvent( CEventName *C.char, CPayload *C.char ) {
  eventName := C.GoString(CEventName)
  payload := C.GoString(CPayload)

  FireSystemEvent(tykcommon.TykEvent(eventName), EventMetaDefault{
    Message: payload,
  })
}
