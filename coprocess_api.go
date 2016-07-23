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

import("fmt")

//export TykStoreData
func TykStoreData( key *C.char, value *C.char, TTL C.int ) {
  // Store or cache some data in Redis, INCR, DECR?
  fmt.Println("storeData\n")
}

//export TykTriggerEvent
func TykTriggerEvent( eventName *C.char, payload *C.char ) {
  // triggers Tyk event
  fmt.Println("triggerEvent\n")
}
