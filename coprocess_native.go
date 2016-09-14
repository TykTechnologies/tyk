// +build coprocess
// +build !grpc

package main

/*
#cgo python CFLAGS: -DENABLE_PYTHON
#include <stdio.h>
#include <stdlib.h>

#include "coprocess/sds/sds.h"

#include "coprocess/api.h"

#ifdef ENABLE_PYTHON
#include "coprocess/python/dispatcher.h"
#include "coprocess/python/binding.h"
#endif

*/
import "C"

import (
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/golang/protobuf/proto"

	"encoding/json"
	"unsafe"
)

// Dispatch prepares a CoProcessMessage, sends it to the GlobalDispatcher and gets a reply.
func (c *CoProcessor) Dispatch(object *coprocess.Object) (newObject *coprocess.Object, err error) {

	var objectMsg []byte

	if MessageType == coprocess.ProtobufMessage {
		objectMsg, _ = proto.Marshal(object)
	} else if MessageType == coprocess.JsonMessage {
		objectMsg, _ = json.Marshal(object)
	}

	objectMsgStr := string(objectMsg)

	var CObjectStr *C.char
	CObjectStr = C.CString(objectMsgStr)

	var objectPtr *C.struct_CoProcessMessage

	objectPtr = (*C.struct_CoProcessMessage)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_CoProcessMessage{}))))
	objectPtr.p_data = unsafe.Pointer(CObjectStr)
	objectPtr.length = C.int(len(objectMsg))

	var newObjectPtr *C.struct_CoProcessMessage
	newObjectPtr = (*C.struct_CoProcessMessage)(GlobalDispatcher.Dispatch(unsafe.Pointer(objectPtr)))

	var newObjectBytes []byte
	newObjectBytes = C.GoBytes(newObjectPtr.p_data, newObjectPtr.length)

	newObject = &coprocess.Object{}

	if MessageType == coprocess.ProtobufMessage {
		proto.Unmarshal(newObjectBytes, newObject)
	} else if MessageType == coprocess.JsonMessage {
		json.Unmarshal(newObjectBytes, newObject)
	}

	C.free(unsafe.Pointer(CObjectStr))
	C.free(unsafe.Pointer(objectPtr))
	C.free(unsafe.Pointer(newObjectPtr))

	return newObject, err
}
